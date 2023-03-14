############ Negando a criação de recursos sem os módulos homologados ############

package terraform2_0 

deny[msg] {
        r = input.configuration.root_module.module_calls[_]
        source := r.source
        not startswith(source, "gcs::https://www.googleapis.com/storage/v1/terraform-modules/")  
        input.resource_changes[_].change.actions[_]  == "create"
        msg =  sprintf("O SOURCE %v não é permitido. \n Favor usar os exemplos README.md", [source])

} 


deny[msg] {
        r = input.configuration.root_module.resources[_]
        address := r.address
        not startswith(address, "gcs::https://www.googleapis.com/storage/v1/terraform-modules/")
        r.mode == "managed"
        input.resource_changes[_].change.actions[_]  == "create"
        msg =  sprintf("O ADDRESS %v não é permitido . \n Favor usar os exemplos em README.md", [address])
} 

################## Negando a criação de instâncias de cloudsql sem SSL ##################
deny[msg] {

        r = input.resource_changes[_]
        r.change.actions[_]  == "create" 
        r.type == "google_sql_database_instance"
        r.change.after.settings[_].ip_configuration[_].require_ssl != true 

        # Excessão para Read replicas
        not r.change.after.master_instance_name  

        msg = "\n Não é permitido o recurso google_sql_database_instance sem conexão SSL." 
} 

################## Negando a alteração de SSL do cloudsql de true para false ##################
deny[msg] {

        r = input.resource_changes[_]
        r.change.actions[_]  == "update" 
        r.type == "google_sql_database_instance"
        r.change.before.settings[_].ip_configuration[_].require_ssl == true
        r.change.after.settings[_].ip_configuration[_].require_ssl != true 

        msg = "\n Não é permitido desabilitar SSL na instância de Cloudsql." 
} 

############## Aprovação manual em ambiente de produção ########################
warn[msg] {
        projects_that_need_approval := [
                "prod",
                "arch",
        ]
        exception := {
                "google_compute_snapshot",
                "google_compute_snapshot_iam_member",
                "google_cloud_scheduler_job",
        }
        status := [
                "create",
                "delete",
                "modify",
                "update",
        ]  

        r = input.resource_changes[_]
        r.change.actions[_]  == status[_]
        project := r.change[_].project
        startswith(project, projects_that_need_approval[_])
        nome := r.type
        not exception[nome]
        msg =  "\n Não é permitido a criação/alteração desse recurso em produção sem aprovação." 
} 

################### Aprovação manual para google_cloud_scheduler_job exceto o scheduler que apaga os snapshots ##################

warn[msg] {
        projects_that_need_approval := [
                "prod",
                "arch",
        ]
        status := [
                "create",
                "delete",
                "modify",
                "update",
        ]  

        r = input.resource_changes[_]
        r.change.actions[_]  == status[_]
        project := r.change[_].project
        startswith(project, projects_that_need_approval[_])
        r.type == "google_cloud_scheduler_job"
        msg =  "\n Não é permitido a criação/alteração desse recurso em produção sem aprovação." 
} 