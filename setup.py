import sys, os
import distutils.cygwinccompiler
import mock

from distutils.core import setup
from Cython.Build import cythonize

def get_msvcr():
    """Include the appropriate MSVC runtime library if Python was built
    with MSVC 7.0 or later.
    """
    msc_pos = sys.version.find('MSC v.')
    if msc_pos != -1:
        msc_ver = sys.version[msc_pos+6:msc_pos+10]
        if msc_ver == '1300':
            # MSVC 7.0
            return ['msvcr70']
        elif msc_ver == '1310':
            # MSVC 7.1
            return ['msvcr71']
        elif msc_ver == '1400':
            # VS2005 / MSVC 8.0
            return ['msvcr80']
        elif msc_ver == '1500':
            # VS2008 / MSVC 9.0
            return ['msvcr90']
        elif msc_ver == '1600':
            # VS2010 / MSVC 10.0
            return ['msvcr100']
        elif msc_ver == '1700':
            # Visual Studio 2012 / Visual C++ 11.0
            return ['msvcr110']
        elif msc_ver == '1800':
            # Visual Studio 2013 / Visual C++ 12.0
            return ['msvcr120']
        elif msc_ver == '1900':
            # Visual Studio 2015 / Visual C++ 14.0
            # "msvcr140.dll no longer exists" http://blogs.msdn.com/b/vcblog/archive/2014/06/03/visual-studio-14-ctp.aspx
            return ['vcruntime140']
        else:
            return ['vcruntime140']
            
def cygwinccompiler_init(self, verbose=0, dry_run=0, force=0):
        distutils.cygwinccompiler.CygwinCCompiler.__init__(self, verbose, dry_run, force)

        # ld_version >= "2.13" support -shared so use it instead of
        # -mdll -static
        if self.ld_version >= "2.13":
            shared_option = "-shared"
        else:
            shared_option = "-mdll -static"

        # A real mingw32 doesn't need to specify a different entry point,
        # but cygwin 2.91.57 in no-cygwin-mode needs it.
        if self.gcc_version <= "2.91.57":
            entry_point = '--entry _DllMain@12'
        else:
            entry_point = ''

        if distutils.cygwinccompiler.is_cygwingcc():
            raise distutils.cygwinccompiler.CCompilerError(
                'Cygwin gcc cannot be used with --compiler=mingw32')

        self.set_executables(compiler='gcc -O -Wall',
                             compiler_so='gcc -mdll -O -Wall',
                             compiler_cxx='g++ -O -Wall',
                             linker_exe='gcc',
                             linker_so='%s %s %s -L %s'
                                        % (self.linker_dll, shared_option,
                                           entry_point, os.path.split(sys.executable)[0].replace("\\", "/")))
        # Maybe we should also append -mthreads, but then the finished
        # dlls need another dll (mingwm10.dll see Mingw32 docs)
        # (-mthreads: Support thread-safe exception handling on `Mingw32')

        # no additional libraries needed
        self.dll_libraries=[]

        # Include the appropriate MSVC runtime library if Python was built
        # with MSVC 7.0 or later.
        self.dll_libraries = get_msvcr()

with mock.patch('distutils.cygwinccompiler.get_msvcr', get_msvcr):
    with mock.patch('distutils.cygwinccompiler.Mingw32CCompiler.__init__', cygwinccompiler_init):
        setup(
            ext_modules = cythonize("decryptor.pyx")
        )
