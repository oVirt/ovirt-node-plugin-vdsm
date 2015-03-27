%include ovirt-node-image.ks
%packages --excludedocs --nobase
ovirt-node-plugin-vdsm
%end
%include vdsm-plugin-minimizer.ks
