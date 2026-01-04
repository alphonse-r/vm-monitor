module "ec2_cluster" {
  source = "./modules/ec2-cluster"

  region             = "us-east-1"
  ami_id             = "ami-05ec1e5f7cfe5ef59"  # Remplace par ton AMI valide
  key_name           = "ansible-key"           # Nom du key pair créé
  web_instance_count = 4                       # Nombre de web targets
}
