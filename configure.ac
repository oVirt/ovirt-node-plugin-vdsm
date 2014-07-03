define([VERSION_MAJOR], [0])
define([VERSION_MINOR], [2])
define([VERSION_FIX], [0])
define([VERSION_NUMBER], VERSION_MAJOR[.]VERSION_MINOR[.]VERSION_FIX)
define([VERSION_SUFFIX], [_master])

AC_INIT([ovirt-node-plugin-vdsm], VERSION_NUMBER[]VERSION_SUFFIX, [node-devel@ovirt.org])
PACKAGE_RPM_VERSION="VERSION_NUMBER"
PACKAGE_RPM_RELEASE="0.0.$(echo VERSION_SUFFIX | sed 's/^_//')"
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability tar-pax])
AC_SUBST([PACKAGE_RPM_VERSION])
AC_SUBST([PACKAGE_RPM_RELEASE])
AC_SUBST([ENGINENAME], ['oVirt Engine'])

AM_PATH_PYTHON

AC_CONFIG_FILES([Makefile
                src/Makefile
                src/config.py
                conf/Makefile
                hooks/Makefile
                recipe/Makefile
                version.ovirt-node-plugin-vdsm
                ovirt-node-plugin-vdsm.spec])
AC_OUTPUT
