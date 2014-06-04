AC_INIT([ovirt-node-plugin-vdsm], [0.1.1], [node-devel@ovirt.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability tar-pax])
AC_SUBST([ENGINENAME], ['oVirt Engine'])

AM_PATH_PYTHON

AC_CONFIG_FILES([Makefile
                src/Makefile
                src/config.py
                conf/Makefile
                hooks/Makefile
                recipe/Makefile
                ovirt-node-plugin-vdsm.spec])
AC_OUTPUT
