resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

resource "azurerm_virtual_network" "rg" {
  name                = "myVnet"
  address_space       = var.vNet_block
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "rg" {
  name                 = "backendSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.rg.name
  address_prefixes     = ["10.1.0.0/24"]
}

resource "azurerm_public_ip" "rg" {
  name                = "PubIPfor${var.rg_name}lb1"
  location            = azurerm_virtual_network.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = "${var.rg_name}lb1"
}

resource "azurerm_lb" "rg" {
  name                = "${var.rg_name}lb1"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard"

  frontend_ip_configuration {
    name                 = "myFrontend"
    public_ip_address_id = azurerm_public_ip.rg.id
  }
}

resource "azurerm_lb_probe" "rg" {
  resource_group_name = azurerm_resource_group.rg.name
  loadbalancer_id     = azurerm_lb.rg.id
  name                = "ssh-running-probe"
  port                = 22
}

resource "azurerm_lb_backend_address_pool" "rg" {
  loadbalancer_id = azurerm_lb.rg.id
  name            = "BackEndAddressPool"
}

resource "azurerm_lb_rule" "rg" {
  resource_group_name            = azurerm_resource_group.rg.name
  loadbalancer_id                = azurerm_lb.rg.id
  name                           = "myHTTPRule"
  protocol                       = "Tcp"
  frontend_port                  = 80
  backend_port                   = 80
  frontend_ip_configuration_name = "myFrontend"
  backend_address_pool_ids        = [azurerm_lb_backend_address_pool.rg.id]
  probe_id                       = azurerm_lb_probe.rg.id
}

resource "azurerm_network_interface" "rg" {
  count               = var.instance_count
  name                = "nic-${count.index}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "config-${count.index}"
    subnet_id                     = azurerm_subnet.rg.id
    private_ip_address_allocation = "Dynamic"
  }
}

locals {
  vm_nics = azurerm_network_interface.rg[*].id
}

# resource "azurerm_network_security_group" "rg" {
#   name                = "myNSG"
#   location            = azurerm_resource_group.rg.location
#   resource_group_name = azurerm_resource_group.rg.name

#   security_rule {
#     name                       = "httpNSGrule"
#     priority                   = 1001
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     destination_port_range     = "80"
#     source_address_prefix      = "*"
#     destination_address_prefix = "*"
#   }
# }

# resource "azurerm_network_interface_security_group_association" "rg" {
#     count = 2
#   network_interface_id   = element(local.vm_nics, count.index)
#   #network_interface_id      = azurerm_network_interface.rg.id
#   network_security_group_id = azurerm_network_security_group.rg.id
# }

resource "azurerm_network_interface_backend_address_pool_association" "rg" {
  count = 2
  network_interface_id   = element(local.vm_nics, count.index)
  ip_configuration_name   = "config-${count.index}"
  backend_address_pool_id = azurerm_lb_backend_address_pool.rg.id
}

resource "azurerm_availability_set" "rg" {
  name                = "availSet-1"
  platform_fault_domain_count = 2
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_linux_virtual_machine" "rg" {
  count                 = var.instance_count
  name                  = "azurevm-${count.index}"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = "Standard_B1s"
  admin_username        = "adminuser"
  network_interface_ids = [azurerm_network_interface.rg[count.index].id]
  availability_set_id   = azurerm_availability_set.rg.id

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS"
    version   = "latest"
  }
}