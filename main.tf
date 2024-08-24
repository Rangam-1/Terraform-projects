terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.61.0"
    }
  }
}
provider "aws" {
  region = "ap-south-1"
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
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8082
    to_port     = 8082
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
    instance_type = "t2.medium"
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
        sudo docker start sonarqube
        sudo hostnamectl set-hostname SonarQube-Server
        sudo echo "All Done" 
   EOF
  }
  output "SonarQube-URL" {
    value = "http://${aws_instance.SonarQube.public_ip}:9000"
  }
resource "aws_instance" "Jfrog" {
    tags = {
      Name = "Jfrog-Server"
    }
    ami = "ami-00060fac2f8c42d30"
    instance_type = "t3.medium"
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
  sudo hostnamectl set-hostname "jfrog.cloudbinary.io"
  echo "`hostname -I | awk '{ print $1}'` `hostname`" >> /etc/hosts
  sudo yum install java-17-amazon-corretto.x86_64 -y
  sudo cp -pvr /etc/environment "/etc/environment_$(date +%F_%R)"
  echo "JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/" >> /etc/environment
  source /etc/environment
  cd /opt/
you will find all the version in https://releases.jfrog.io/artifactory/bintray-artifactory/org/artifactory/oss/jfrog-artifactory-oss/
  sudo wget https://releases.jfrog.io/artifactory/bintray-artifactory/org/artifactory/oss/jfrog-artifactory-oss/7.71.3/jfrog-artifactory-oss-7.71.3-linux.tar.gz
  sudo tar -xvzf jfrog-artifactory-oss-7.71.3-linux.tar.gz
  mv artifactory-oss-* jfrog  
  sudo cp -pvr /etc/environment "/etc/environment_$(date +%F_%R)"  
  echo "JFROG_HOME=/opt/jfrog" >> /etc/environment
  # sudo vi /etc/systemd/system/artifactory.service --> you can do it manually by using vi editor
  echo "[Unit]" > /etc/systemd/system/artifactory.service
  echo "Description=JFrog artifactory service" >> /etc/systemd/system/artifactory.service
  echo "After=syslog.target network.target" >> /etc/systemd/system/artifactory.service
  echo "[Service]" >> /etc/systemd/system/artifactory.service
  echo "Type=forking" >> /etc/systemd/system/artifactory.service
  echo "ExecStart=/opt/jfrog/app/bin/artifactory.sh start" >> /etc/systemd/system/artifactory.service
  echo "ExecStop=/opt/jfrog/app/bin/artifactory.sh stop" >> /etc/systemd/system/artifactory.service
  echo "User=root" >> /etc/systemd/system/artifactory.service
  echo "Group=root" >> /etc/systemd/system/artifactory.service 
  echo "Restart=always" >> /etc/systemd/system/artifactory.service
  echo "[Install]" >> /etc/systemd/system/artifactory.service
  echo "WantedBy=multi-user.target" >> /etc/systemd/system/artifactory.service
  sudo systemctl daemon-reload
  sudo systemctl enable artifactory.service
  sudo systemctl restart artifactory.service
     EOF
  }
  output "Jfrog-URL" {
    value = "http://${aws_instance.Jfrog.public_ip}:8081"
  }
  resource "aws_instance" "Tomcat" {
    tags = {
      Name = "Tomcat-Server"
    }
    ami = "ami-00060fac2f8c42d30"
    instance_type = "t3.medium"
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
  !/bin/bash
  sudo hostnamectl set-hostname "Tomcat.cloudbinary.io"
  echo "`hostname -I | awk '{ print $1}'` `hostname`" >> /etc/hosts
  sudo yum install java-17-amazon-corretto.x86_64 -y
  sudo cp -pvr /etc/environment "/etc/environment_$(date +%F_%R)"
  echo "JAVA_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64/" >> /etc/environment
  source /etc/environment
  cd /opt/
  sudo wget https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.93/bin/apache-tomcat-9.0.93.tar.gz
  sudo tar -xvzf apache-tomcat-9.0.93.tar.gz
  mv apache-tomcat-9.0.93 tomcat
  sudo cp -pvr /etc/environment "/etc/environment_$(date +%F_%R)"
  sudo sed -i '$d' /opt/tomcat/conf/tomcat-users.xml
  echo '<role rolename="manager-gui"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<role rolename="manager-script"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<role rolename="manager-jmx"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<role rolename="manager-status"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<role rolename="admin-gui"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<role rolename="admin-script"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<user username="venky" password="venky" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script"/>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '</tomcat-users>' >> /opt/tomcat/conf/tomcat-users.xml
  echo '<?xml version="1.0" encoding="UTF-8"?>' > /opt/tomcat/webapps/manager/META-INF/context.xml
  echo '<Context antiResourceLocking="false" privileged="true" >' >> /opt/tomcat/webapps/manager/META-INF/context.xml
  echo '<CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor" sameSiteCookies="strict" />' >> /opt/tomcat/webapps/manager/META-INF/context.xml
  echo '<Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruC    ache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>' >> /opt/tomcat/webapps/manager/META-INF/context.xml
  echo '</Context>' >> /opt/tomcat/webapps/manager/META-INF/context.xml
  sudo sh /opt/tomcat/bin/startup.sh
     EOF
  }
  output "Tomcat-URL" {
    value = "http://${aws_instance.Tomcat.public_ip}:8080"
  }
