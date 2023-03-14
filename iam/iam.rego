package iam

############### Permitir apenas recursos de iam ###############

deny[msg] {
        approved_resources  := {
                "google_project_iam_member",
                "google_folder_iam_member",
                "google_organization_iam_member",
                "google_project_iam_custom_role",
                "google_organization_iam_custom_role",
                "google_service_account",
                "google_secret_manager_secret", 
                "google_secret_manager_secret_iam_member",
                "google_secret_manager_secret_version",
                "google_service_account_key",
                "random_id",
                "google_storage_bucket_iam_member",
                "google_pubsub_topic_iam_member",
                "google_pubsub_subscription_iam_member",
                "google_compute_instance_iam_member",
                "google_cloudfunctions_function_iam_member",
                "google_dataproc_cluster_iam_member",
                "google_bigtable_instance_iam_member",
                "google_bigtable_table_iam_member",
                "google_notebooks_instance_iam_member",
                "google_notebooks_runtime_iam_member",
                "google_bigquery_dataset_iam_member",
                "google_bigquery_table_iam_member",
                "google_artifact_registry_repository_iam_member",
                "google_service_account_iam_member",
        }
        status := [
                "create",
                "delete",
                "modify",
                "update",
        ]  
        r = input.resource_changes[_]
        nome := r.type
        not approved_resources[nome]
        r.change.actions[_] == status[_]
        msg =  sprintf("\n Não é permitido a utilização do recurso %v .", [nome])
} 

############## Aprovação em ambientes de produção ########################
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
        msg =  "\n Não é permitido a criação/alteração desse recurso em produção sem aprovação." 
} 

################## Aprovação para criação, deleção e modificação de determinados recursos ##################
warn[msg] {
        resources_that_need_approval := {
                "google_folder_iam_member",
                "google_organization_iam_member",
                "google_organization_iam_custom_role",
                "google_project_iam_custom_role",
                "google_secret_manager_secret",
                "google_storage_hmac_key",
        }
        status := [
                "create",
                "delete",
                "modify",
                "update",
        ]  
        r = input.resource_changes[_]
        nome := r.type
        r.change.actions[_]  == status[_]
        resources_that_need_approval[nome]
        msg =  sprintf("\n Não é permitido o recurso %v sem aprovação.", [nome])
} 

################## Aprovação para determinadas Roles a nível de projeto ##################
warn[msg] {
        roles_that_need_approval := [ 
                "roles/storage",
                "roles/pubsub",
                "roles/compute",
                "roles/cloudfunctions",
                "roles/dataproc.",
                "roles/bigtable.",
                "roles/notebooks.",
                "roles/bigquery.",
                "roles/secretmanager.",
        ]
        roles_exception := { 
                "roles/compute.networkUser",
                "roles/compute.networkViewer",
        }
        status := [
                "create",
                "modify",
                "update",
        ]  
        r = input.resource_changes[_]
        r.type == "google_project_iam_member"
        r.change.actions[_]  == status[_]
        role = r.change[_].role
        contains(role, roles_that_need_approval[_])
        not roles_exception[role]
        msg =  sprintf("\n Não é permitida a %v a nível de projeto sem aprovação!", [role])
} 

############### Aprovação para determinadas Roles ################## 

warn[msg] {
        roles_that_need_approval := [ 
                "roles/viewer",
                "roles/editor",
                "roles/owner",
                "roles/iam.",
                "roles/securitycenter.",
                "roles/resourcemanager.",
                ".admin",
                ".owner",
                "projects/",
                "organizations/",
        ]
        status := [
                "create",
                "modify",
                "update",
        ] 
        r = input.resource_changes[_]
        r.change.actions[_]  == status[_]
        role = r.change[_].role
        contains(role, roles_that_need_approval[_])
        role != "roles/iam.workloadIdentityUser"
        msg =  sprintf("\n Não é permitido a %v sem aprovação.", [role])
} 


############### Aprovação para buckets em produção ################## 

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
        r.type == "google_storage_bucket_iam_member"
        contains(r.change[_].member, projects_that_need_approval[_])
        msg =  "\n  Não é permitido a criação/alteração desse recurso em produção sem aprovação"
} 


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
        r.type == "google_storage_bucket_iam_member"
        bucket = r.change[_].bucket

        p = input.prior_state.values.root_module.child_modules[_].resources[_]
        p.mode == "data"
        project = p.values.project 
        bucket == p.values.name 
        startswith(project, projects_that_need_approval[_])

        msg =  sprintf("\n  Não é permitido a criação/alteração do bucket %v em produção sem aprovação", [bucket])
} 


############### Aprovação para grupos do GCP ################## 

warn[msg] {
        status := [
                "create",
                "delete",
                "modify",
                "update",
        ]  
        r = input.resource_changes[_]
        r.change.actions[_]  == status[_]
        startswith(r.change[_].member, "group:")
        msg =  "\n  Não é permitido alteração em grupo sem aprovação"
} 