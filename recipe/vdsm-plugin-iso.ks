%include ovirt-node-image.ks
%packages --excludedocs --nobase
ovirt-node-plugin-vdsm
ovirt-node-plugin-hosted-engine
%end
%include vdsm-plugin-minimizer.ks
