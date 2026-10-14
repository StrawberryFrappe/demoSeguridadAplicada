# Laboratorio aislado de 2 VMs para la demo de CSRF + Broken Auth.
# Red host-only 192.168.56.0/24. No expone nada a internet.
Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"

  config.vm.define "victim" do |v|
    v.vm.hostname = "victim"
    v.vm.network "private_network", ip: "192.168.56.10"
    v.vm.provision "shell", path: "provision/victim.sh"
    v.vm.provider "virtualbox" do |vb|
      vb.name = "demo-victim"
      vb.memory = 2048
      vb.cpus = 2
    end
  end

  config.vm.define "attacker" do |a|
    a.vm.hostname = "attacker"
    a.vm.network "private_network", ip: "192.168.56.11"
    a.vm.provision "shell", path: "provision/attacker.sh"
    a.vm.provider "virtualbox" do |vb|
      vb.name = "demo-attacker"
      vb.memory = 1024
      vb.cpus = 1
    end
  end
end
