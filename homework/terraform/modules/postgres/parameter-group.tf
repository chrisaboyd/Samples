resource "aws_db_parameter_group" "rds_parameter_group" {
  count  = var.rds_aurora ? 0 : 1
  name   = "rds-pg"
  family = "postgres14"

  parameter {
    name         = "max_connections"
    value        = 250 # 2500 is too large for t4g.large
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "max_locks_per_transaction"
    value        = 500
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "work_mem"
    value        = 2048 # 4096 # (12 * 1024) too large for t4g.large
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "maintenance_work_mem"
    value        = 65535 # 64mb for t4g.large# (128 * 1024) # 1024 * min(floor(32768 / 8), 2048) too large for t4g.large
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "shared_buffers"
    value        = 65535 # 1024MB, 1/8th of t4g memory # 1024 * min(floor(32768 / 4), 2048)
    apply_method = "pending-reboot"
  }
}
resource "aws_db_parameter_group" "aurora_parameter_group" {
  count  = var.rds_aurora ? 1 : 0
  name   = "aurora-pg"
  family = "aurora-postgresql14"

  parameter {
    name         = "max_connections"
    value        = 2500
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "max_locks_per_transaction"
    value        = 500
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "work_mem"
    value        = (12 * 1024)
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "maintenance_work_mem"
    value        = 1024 * min(floor(32768 / 8), 2048)
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "shared_buffers"
    value        = 1024 * min(floor(32768 / 4), 2048)
    apply_method = "pending-reboot"
  }
}
