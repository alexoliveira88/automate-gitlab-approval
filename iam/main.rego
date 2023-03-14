############ Negando a criação de recursos sem os módulos homologados ############

package main 

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




