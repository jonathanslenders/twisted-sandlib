# encoding: utf-8

"""
Twisted implementation for Pypy sandboxing wrapper (pypy's sandlib).
"""

import errno
import os
import posixpath
import select
import signal
import stat
import subprocess
import sys
import termcolor
import StringIO

from pypy.tool.lib_pypy import import_from_lib_pypy, LIB_ROOT


try:
    from rpython.translator.sandbox.vfs import Dir, File, RealDir, FSObject, RealFile
    from rpython.translator.sandbox.vfs import UID, GID
except ImportError:
    from pypy.translator.sandbox.vfs import Dir, File, RealDir, FSObject, RealFile
    from pypy.translator.sandbox.vfs import UID, GID

from twisted.internet import reactor, abstract, fdesc, defer, protocol
from twisted.python import log

marshal = import_from_lib_pypy('marshal')

TIMEOUT = 1000


# ===================================[ Sandbox Input / Output marshalling ]====================

# keep the table in sync with rsandbox.reraise_error()
EXCEPTION_TABLE = [
    (1, OSError),
    (2, IOError),
    (3, OverflowError),
    (4, ValueError),
    (5, ZeroDivisionError),
    (6, MemoryError),
    (7, KeyError),
    (8, IndexError),
    (9, RuntimeError),
    ]

# Non-marshal result types
RESULTTYPE_STATRESULT = object()
RESULTTYPE_LONGLONG = object()


class StringIOWithEOF(StringIO.StringIO):
    """
    Same as StringIO, but raises EOF when reading
    past the end. This is required for marshall.
    """
    def read(self, n=-1):
        result = StringIO.StringIO.read(self, n)

        if n > 0 and len(result) < n:
            raise EOFError
        return result


class PyPyProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, startedCallback, receivedCallback, doneCallback):
        self.startedCallback = startedCallback
        self.receivedCallback = receivedCallback
        self.doneCallback = doneCallback
        self._buffer = []

    def connectionMade(self):
        # Process started
        self.startedCallback()

    def outReceived(self, data):
        try:
            # Try to parse what we have received until now
            io = StringIOWithEOF(''.join(self._buffer + [data]))

            fname = marshal.load(io)
            args = marshal.load(io)

            # Unmarshalling succeeded, call callback
            self.receivedCallback(fname, args)

            # Keep the remainder for the next time.
            remainder = io.read()
            self._buffer = [ remainder ]

            # In case we did receive multiple syscalls in
            # one chunk, immediately parse again.
            if len(remainder):
                self.outReceived('')
        except EOFError, e:
            # Not enough data, wait for the next part to arrive
            if data:
                self._buffer.append(data)

    def errReceived(self, data):
        log.msg('Received err from child process: %s' % str(data))

    def outConnectionLost(self):
        pass

    def processEnded(self, status):
        self.doneCallback(status)

    # Protocol implementation (see also: pypy/translator/sandbox/sandlib.py)

    def write_message(self, msg, resulttype=None):
        if resulttype is None:
            if sys.version_info < (2, 4):
                marshal.dump(msg, self.transport)
            else:
                marshal.dump(msg, self.transport, 0)

        elif resulttype is RESULTTYPE_STATRESULT:
            # Hand-coded marshal for stat results that mimics what rmarshal expects.
            # marshal.dump(tuple(msg)) would have been too easy. rmarshal insists
            # on 64-bit ints at places, even when the value fits in 32 bits.
            import struct
            st = tuple(msg)
            fmt = "iIIiiiIfff"
            buf = []
            buf.append(struct.pack("<ci", '(', len(st)))
            for c, v in zip(fmt, st):
                if c == 'i':
                    buf.append(struct.pack("<ci", c, v))
                elif c == 'I':
                    buf.append(struct.pack("<cq", c, v))
                elif c == 'f':
                    fstr = "%g" % v
                    buf.append(struct.pack("<cB", c, len(fstr)))
                    buf.append(fstr)
            self.transport.write(''.join(buf))
        elif resulttype is RESULTTYPE_LONGLONG:
            import struct
            self.transport.write(struct.pack("<cq", 'I', msg))
        else:
            raise Exception("Can't marshal: %r (%r)" % (msg, resulttype))

    def write_exception(self, exception, tb=None):
        for i, excclass in EXCEPTION_TABLE:
            if isinstance(exception, excclass):
                self.write_message(i)
                if excclass is OSError:
                    error = exception.errno
                    if error is None:
                        error = errno.EPERM
                    self.write_message(error)
                break
        else:
            # just re-raise the exception
            raise exception.__class__, exception, tb


# ===================================[ Sandbox ]===========================


class Sandbox(object):
    executable = '/opt/pypy-sandbox/pypy/translator/goal/pypy-c'
    arguments = [ '-S', '-u'  ] # '--timeout', str(TIMEOUT)]
    startup_file = '/application/main.py'
    argv0 = '/bin/pypy-c'
    python_params = []
    virtual_cwd = '/'
    virtual_fd_range = range(3, 50)
    virtual_console_isatty = True
    enable_debugging = False

    def __init__(self):
        self.virtual_root = self.build_virtual_root()
        self.open_fds = { } # {virtual_fd: (read_file_object, node)}
        self.virtual_env = {
                'PYTHONPATH': '',# ':'.join([ # Actually, it's not even necessary to add this paths.
                                 #   '/bin',
                                 #   '/bin/pypy',
                                 #   '/bin/pypy/bin', ])
                #'PYPY_GC_DEBUG': '0'
                }
        self.process_protocol = None
        self.is_running = False

    def debug(self, string):
        if self.enable_debugging:
            print termcolor.colored(string, 'red')

    def start(self):
        self.process_protocol = PyPyProcessProtocol(self._process_started, self.message_received, self._process_done)

        reactor.spawnProcess(self.process_protocol, self.executable, args=[self.argv0] + self.arguments + [self.startup_file] + self.python_params,
                                env=self.virtual_env, path=self.virtual_cwd, usePTY=False)

    def _process_started(self):
        self.is_running = True

    def _process_done(self, status):
        log.msg('Pypy sandbox process done, status=%s' % status.value)
        self.is_running = False
        self.done(status)

    def message_received(self, fname, args):
        """
        System call coming from sandbox environment.
        """
        # Syscall success callback
        def message_processed(answer, resulttype):
            try:
                self.process_protocol.write_message(0) # Error code - 0 for ok
                self.process_protocol.write_message(answer, resulttype)
            except (IOError, OSError):
                # Likely cause: subprocess is dead, child_stdin closed.
                pass

        # Syscall error callback
        def message_processed_error(e):
            self.debug('Exception= %s' % str(e))
            #tb = sys.exc_info()[2] # TODO: check this
            self.process_protocol.write_exception(e.value, e.tb)

        # Retreive syscall handler
        try:
            # Don't allow names starting with underscores.
            if '__' in fname:
                raise ValueError('Unsafe fname')

            try:
                self.debug('Syscall: fname=%s args=%s' % (str(fname), str(args)))
                handler = getattr(self, 'do_' + fname.replace('.', '__'))
            except AttributeError:
                raise RuntimeError('No handler for this function: %s' % fname)

            # Retreive handler type
            resulttype = getattr(handler, 'resulttype', None)

            # Call handler
            d = handler(*args)
            d.addCallback(message_processed, resulttype)
            d.addErrback(message_processed_error)

        except Exception, e:
            tb = sys.exc_info()[2]
            self.process_protocol.write_exception(e, tb)

    def done(self):
        """
        Sandbox is finished.
        """
        pass # Override

    def kill(self):
        """
        Terminate sandbox.
        """
        if self.is_running:
            self.process_protocol.transport.signalProcess('KILL')

    def stdout_write(self, data):
        sys.__stdout__.write(data)

    def stderr_write(self, data):
        sys.__stderr__.write(data)

    def stdin_read(self, size):
        data = sys.__stdin__.read(size)
        return defer.succeed(data)

    def translate_path(self, vpath):
        # XXX this assumes posix vpaths for now, but os-specific real paths
        vpath = posixpath.normpath(posixpath.join(self.virtual_cwd, vpath))
        dirnode = self.virtual_root
        components = vpath.split('/')
        for component in components[:-1]:
            if component:
                dirnode = dirnode.join(component)
                if dirnode.kind != stat.S_IFDIR:
                    raise OSError(errno.ENOTDIR, component)
        return (dirnode, components[-1])


    def get_node(self, vpath):
        dirnode, name = self.translate_path(vpath)

        if name:
            node = dirnode.join(name)
        else:
            node = dirnode
        self.debug('%r => %r' % (vpath, node))
        return node

    def allocate_fd(self, f, node=None):
        for fd in self.virtual_fd_range:
            if fd not in self.open_fds:
                self.open_fds[fd] = (f, node)
                return fd
        else:
            raise OSError(errno.EMFILE, "trying to open too many files")

    def get_fd(self, fd, throw=True):
        """Get the objects implementing file descriptor `fd`.

        Returns a pair, (open file, vfs node)

        `throw`: if true, raise OSError for bad fd, else return (None, None).
        """
        try:
            f, node = self.open_fds[fd]
        except KeyError:
            if throw:
                raise OSError(errno.EBADF, "bad file descriptor")
            return None, None
        return f, node

    def get_file(self, fd, throw=True):
         """Return the open file for file descriptor `fd`."""
         return self.get_fd(fd, throw)[0]

    def do_ll_os__ll_os_open(self, vpathname, flags, mode):
        self.debug('Opening file: %s' % vpathname)

        # Get filesystem node
        try:
            node = self.get_node(vpathname)
        except OSError, e:
            return defer.fail(e)

        # Read-only mode files cannot be opened in write mode
        if node.read_only and flags & (os.O_RDONLY|os.O_WRONLY|os.O_RDWR) != os.O_RDONLY:
            return defer.fail(OSError(errno.EPERM, "write access denied"))

        # All other flags are ignored
        f = node.open()
        return defer.succeed(self.allocate_fd(f, node))

    def do_ll_os__ll_os_close(self, fd):
        f = self.get_file(fd)
        del self.open_fds[fd]
        f.close()

        return defer.succeed(None)

    def do_ll_os__ll_os_getenv(self, name):
        return defer.succeed(self.virtual_env.get(name))

    def do_ll_os__ll_os_envitems(self):
        return defer.succeed(self.virtual_env.items())

    def do_ll_os__ll_os_write(self, fd, data):
        if fd == 1:
            self.stdout_write(data)
            return defer.succeed(len(data))
        elif fd == 2:
            self.stderr_write(data)
            return defer.succeed(len(data))
        else:
            f, node = self.get_fd(fd)
            if node and not node.read_only:
                return defer.succeed(f.write(data))

        raise OSError('Trying to write to fd %d' % fd)

    def do_ll_os__ll_os_read(self, fd, size):
        if fd == 0:
            return self.stdin_read(size)
        else:
            f = self.get_file(fd, throw=False)

            if f is None:
                return defer.fail(OSError('trying to read to fd %d' % fd))
            else:
                if not (0 <= size <= sys.maxint):
                    return defer.fail(OSError(errno.EINVAL, "invalid read size"))

                # don't try to read more than 256KB at once here
                #read_result = f.read(min(size, 256*1024))

                return defer.maybeDeferred(f.read, min(size, 256*1024))

    def do_ll_os__ll_os_stat(self, vpathname):
        try:
            node = self.get_node(vpathname)
            return defer.succeed(node.stat())
        except OSError, e:
            return defer.fail(e)

    do_ll_os__ll_os_stat.resulttype = RESULTTYPE_STATRESULT
    do_ll_os__ll_os_lstat = do_ll_os__ll_os_stat


    def do_ll_os__ll_os_fstat(self, fd):
        try:
            f, node = self.get_fd(fd)
            return defer.succeed(node.stat())
        except OSError, e:
            return defer.fail(e)

    do_ll_os__ll_os_fstat.resulttype = RESULTTYPE_STATRESULT

    def do_ll_os__ll_os_strerror(self, errnum):
        # unsure if this shouldn't be considered safeboxsafe
        return defer.succeed(os.strerror(errnum) or ('Unknown error %d' % (errnum,)))

    def do_ll_os__ll_os_listdir(self, vpathname):
        node = self.get_node(vpathname)
        return defer.succeed(node.keys())

    def do_ll_os__ll_os_getuid(self):
        return defer.succeed(UID)
    do_ll_os__ll_os_geteuid = do_ll_os__ll_os_getuid

    def do_ll_os__ll_os_getgid(self):
        return defer.succeed(GID)
    do_ll_os__ll_os_getegid = do_ll_os__ll_os_getgid

    def do_ll_os__ll_os_getcwd(self):
        return defer.succeed(self.virtual_cwd)

    def do_ll_os__ll_os_isatty(self, fd):
        return defer.succeed(self.virtual_console_isatty and fd in (0, 1, 2))


    # Virtual root

    def build_virtual_root(self):
        # build a virtual file system:
        exclude = ['.pyc', '.pyo']
        libroot = str(LIB_ROOT)

        tree = {
            'bin': Dir({
                # * can access its own executable
                'pypy-c': RealFile(self.executable),

                # * can access the pure Python libraries
                'lib-python': RealDir(os.path.join(libroot, 'lib-python'), exclude=exclude),
                'lib_pypy': RealDir(os.path.join(libroot, 'lib_pypy'), exclude=exclude),
              }),
        }
        tree.update(self.extend_virtual_root())
        return Dir(tree)

    def extend_virtual_root(self):
        # Override this one!
        return {
                    'application': Dir({
                        'main.py': File('print "Hello world" ')
                    })
               }
