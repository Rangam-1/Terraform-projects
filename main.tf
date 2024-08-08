terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.61.0"
    }
  }
}
provider "aws" {
  region = "eu-central-1"
  profile = "default"
}
resource "aws_vpc" "vpc" {
  tags = {
    Name = "CustomisedVpc"
  }
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  assign_generated_ipv6_cidr_block = false
}
resource "aws_internet_gateway" "internet_gateway" {
  tags = {
    Name = "CustomisedInternetGateway"
  }
  vpc_id = aws_vpc.vpc.id
}
resource "aws_subnet" "PublicSubnet" {
  tags = {
    Name = "PublicSubnet"
  }
  vpc_id = aws_vpc.vpc.id
  cidr_block = "10.0.0.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-1a"
}
resource "aws_route_table" "PublicRouteTable" {
  tags = {
    Name = "PublicRouteTable"
  }
  vpc_id = aws_vpc.vpc.id
}
resource "aws_route" "PublicRoute" {
  route_table_id = aws_route_table.PublicRouteTable.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.internet_gateway.id
}  
resource "aws_route_table_association" "PublicRouteTableAssociation" {
  subnet_id = aws_subnet.PublicSubnet.id
  route_table_id = aws_route_table.PublicRouteTable.id
}
resource "aws_security_group" "SecurityGroup" {
  name        = "CustomisedSecurityGroup"
  vpc_id      = aws_vpc.vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "Jenkins" {
  tags = {
    Name = "Jenkins-Server"
  }
  ami = "ami-00060fac2f8c42d30"
  instance_type = "t2.micro"
  key_name = "rangam"
  vpc_security_group_ids = [aws_security_group.SecurityGroup.id]
  subnet_id = aws_subnet.PublicSubnet.id
  associate_public_ip_address = true
  iam_instance_profile = "ssm"
  user_data = <<-EOF
    #!/bin/bash
    sudo yum update -y
    sudo yum install java-17-amazon-corretto.x86_64 -y
    sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
    sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key
    sudo yum upgrade -y
    sudo yum install jenkins -y
    sudo systemctl start jenkins
    sudo systemctl status jenkins
    sudo yum install git -y
    sudo yum install httpd -y
    sudo systemctl start httpd
    sudo hostnamectl set-hostname Jenkins-Server
    sudo echo "Welcome to Jenkins-Server" > /var/www/html/index.html
    EOF
  provisioner "remote-exec" {
    inline = [
         "sleep 60",
         "sudo chown -R jenkins:jenkins /var/lib/jenkins",
         "sudo chmod -R 755 /var/lib/jenkins",
         "sudo -u jenkins cat /var/lib/jenkins/secrets/initialAdminPassword"
    ]
    connection {
      type        = "ssh"
      user        = "ec2-user" # or the appropriate user for your instance
      private_key = file("C:/Users/venki/OneDrive/Desktop/keypair/rangam.pem")
      host        = aws_instance.Jenkins.public_ip
    }
  }
  }
  output "Jenkins-URL" {
    value = "http://${aws_instance.Jenkins.public_ip}:8080"
  }
  resource "aws_instance" "SonarQube" {
    tags = {
      Name = "SonarQube-Server"
    }
    ami = "ami-00060fac2f8c42d30"
    instance_type = "t2.micro"
    key_name = "rangam"
    iam_instance_profile = "ssm"
    vpc_security_group_ids = [aws_security_group.SecurityGroup.id]
    subnet_id = aws_subnet.PublicSubnet.id
    associate_public_ip_address = true
    root_block_device {
      volume_size = 40
      volume_type = "gp2"
    }
    user_data = <<-EOF
        #!/bin/bash
        sudo yum update -y
        sudo yum install java-17-amazon-corretto.x86_64 -y
        sudo yum install docker -y
        sudo systemctl start docker
        sudo systemctl enable docker
        #sudo usermod -a -G docker ec2-user
        sudo docker volume create sonarqube_data
        sudo docker volume create sonarqube_extensions
        sudo docker volume create sonarqube_logs
        sudo docker volume ls
        sudo echo "Welcome to SonarQube-Server"
        sudo docker run -d --name sonarqube -p 9000:9000 -v sonarqube_data:/opt/sonarqube/data -v sonarqube_extensions:/opt/sonarqube/extensions -v sonarqube_logs:/opt/sonarqube/logs sonarqube:lts-community
        sudo docker ps
        sudo hostnamectl set-hostname SonarQube-Server
        sudo echo "All Done" 
   EOF
  }
  output "SonarQube-URL" {
    value = "http://${aws_instance.SonarQube.public_ip}:9000"
  }