<#
   This script will deploy and upgrade elastic
   Usage:
    Example 1: deploy.ps1 -customername  "tsetcustomername"  # This will deploy or upgrade instance of elastic deployed
    Example 1: deploy.ps1 -customername  "tsetcustomername"  -dev # Adding Dev switch will point towards a dev instance for authentication
    Example 1: deploy.ps1 -customername  "tsetcustomername"  -dev -ingressforce # Adding ingressforce switch will upfate ingress
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [String]$customername,

  [switch]$dev, 

  [switch]$ingressforce

)

#$ingressforce = $false

Write-Output "Current path $PSScriptRoot"
#region variables

$nsg = "<REPNGSNAME>" # Network Security Group for AKS
$nsgRule = "<REPNGSRULENAME" # Network Security Group inbound rule name 
$devTenant = "REPTENANTID" # Dev Mode will only be used when dev switch is applied

#endregion

# Get the aks credentials
az aks get-credentials -g $env:rg -n $env:aks --admin
$namespace = kubectl get namespaces -o NAME
$namespace = $namespace.Split('/') | ?{$_ -ne "namespace"}
if($namespace -contains $customername){
    Write-Warning "Namespace $customername already exist in cluster $env:aks " 
}
else{
    Write-Output "Createing Namespace: $customername in cluster $env:aks ...." 
    kubectl create namespace $customername 
}

kubectl config set-context --current --namespace=$customername
$secrets = kubectl.exe get secrets -n $customername -o NAME
$secretsToDeploy = $secrets.Split('/') | ?{$_ -ne "secret"}

if($dev){
    $temp = Get-Content -Path  "$PSScriptRoot\global\config.yml"
    $temp = $temp -replace "<REPPRODTENANTID>" , $devTenant
    $temp > "$PSScriptRoot\global\config.yml"
}

#region elk
# SSL Create
# Root CA

openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -days 3650 -key root-ca-key.pem -out root-ca.pem -subj "/C=IN/ST=KA/L=Bangalore/O=MyOrg/OU=Test/CN=root" 

# Admin cert
openssl genrsa -out admin-kMyOrg-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in admin-kMyOrg-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-kMyOrg.pem
openssl req -new -kMyOrg admin-kMyOrg.pem -out admin.csr -subj "/C=IN/ST=KA/L=Bangalore/O=MyOrg/OU=Test/CN=admin" 
openssl x509 -req -days 3650 -in admin.csr -CA root-ca.pem -CAkMyOrg root-ca-kMyOrg.pem -CAcreateserial -sha256 -out admin.pem

# Node cert
$nodename = $customername + '-elk-master'
openssl genrsa -out node-kMyOrg-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in node-kMyOrg-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-kMyOrg.pem
openssl req -new -kMyOrg node-kMyOrg.pem -out node.csr -subj "/C=IN/ST=KA/L=Bangalore/O=MyOrg/OU=Test/CN=$nodename" 
openssl x509 -req -days 3650 -in node.csr -CA root-ca.pem -CAkMyOrg root-ca-kMyOrg.pem -CAcreateserial -sha256 -out node.pem

# Client cert
openssl genrsa -out client-kMyOrg-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in client-kMyOrg-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out client-kMyOrg.pem
openssl req -new -kMyOrg client-kMyOrg.pem -out client.csr -subj "/C=IN/ST=KA/L=Bangalore/O=MyOrg/OU=Test/CN=*.svc.cluster.local" 
openssl x509 -req -days 3650 -in client.csr -CA root-ca.pem -CAkMyOrg root-ca-kMyOrg.pem -CAcreateserial -sha256 -out client.pem

if($secretsToDeploy | ?{$_ -contains "kibana-certs"}){
    Write-Output "kibana-certs already exist" 
}
else{
    Write-Output "Creating kibana-certs..." 
    kubectl create secret generic kibana-certs --from-file=kibana-kMyOrg.pem=client-kMyOrg.pem --from-file=kibana-crt.pem=client.pem --from-file=kibana-root-ca.pem=root-ca.pem
}
if($secretsToDeploy | ?{$_ -contains "elasticsearch-admin-certs"}){
    Write-Output "elasticsearch-admin-certs already exist"
}
else{
    Write-Output "Creating elasticsearch-admin-certs..."
    kubectl create secret generic elasticsearch-admin-certs --from-file=admin-kMyOrg.pem=admin-kMyOrg.pem --from-file=admin-crt.pem=admin.pem --from-file=admin-root-ca.pem=root-ca.pem
}
if($secretsToDeploy | ?{$_ -contains "elasticsearch-rest-certs"}){
    Write-Output "elasticsearch-rest-certs already exist"
}
else{
    Write-Output "Creating elasticsearch-rest-certs..."
    kubectl create secret generic elasticsearch-rest-certs --from-file=elk-rest-kMyOrg.pem=node-kMyOrg.pem --from-file=elk-rest-crt.pem=node.pem --from-file=elk-rest-root-ca.pem=root-ca.pem
}
if($secretsToDeploy | ?{$_ -contains "elasticsearch-transport-certs"}){
    Write-Output "elasticsearch-transport-certs already exist"
}
else{
    Write-Output "Creating elasticsearch-transport-certs..."
    kubectl create secret generic elasticsearch-transport-certs --from-file=elk-transport-kMyOrg.pem=node-kMyOrg.pem --from-file=elk-transport-crt.pem=node.pem --from-file=elk-transport-root-ca.pem=root-ca.pem
}
if($secretsToDeploy | ?{$_ -contains "internal-users-config"}){
    Write-Output "internal-users-config already exist"
}
else{
    Write-Output "Creating internal-users-config..."
    kubectl create secret generic internal-users-config --from-file="$PSScriptRoot\global\internal_users.yml"
}
if($secretsToDeploy | ?{$_ -contains "roles"}){
    Write-Output "roles already exist"
}
else{
    Write-Output "Creating roles..."
    kubectl create secret generic roles --from-file="$PSScriptRoot\global\roles.yml"
}
if($secretsToDeploy | ?{$_ -contains "role-mapping"}){
    Write-Output "role-mapping already exist"
}
else{
    Write-Host "Creating role-mapping..."
    kubectl create secret generic role-mapping --from-file="$PSScriptRoot\global\roles_mapping.yml"
}
if($secretsToDeploy | ?{$_ -contains "action-groups"}){
    Write-Output "action-groups already exist"
}
else{
    Write-Output "Creating action-groups..."
    kubectl create secret generic action-groups --from-file="$PSScriptRoot\global\action_groups.yml"
}
if($secretsToDeploy | ?{$_ -contains "tenants"}){
    Write-Output "tenants already exist"
}
else{
    Write-Output "Creating tenants..."
    kubectl create secret generic tenants --from-file="$PSScriptRoot\global\tenants.yml"
}
if($secretsToDeploy | ?{$_ -contains "security-config"}){
    Write-Output "security-config already exist"
}
else{
    Write-Output "Creating security-config..."
    kubectl create secret generic security-config --from-file="$PSScriptRoot\global\config.yml"
}

$username = $(az keyvault secret show --name "username" --vault-name $env:kv --query 'value' -o tsv)
$password = $(az keyvault secret show --name "password" --vault-name $env:kv --query 'value' -o tsv)
$cookie = $(az keyvault secret show --name "cookie" --vault-name $env:kv --query 'value' -o tsv)
$lsusername = $(az keyvault secret show --name "lsusername" --vault-name $env:kv --query 'value' -o tsv)
$lspassword = $(az keyvault secret show --name "lspassword" --vault-name $env:kv --query 'value' -o tsv)
$clientsecret = $(az keyvault secret show --name "clientsecret" --vault-name $env:kv --query 'value' -o tsv)
$clientid = $(az keyvault secret show --name "clientid" --vault-name $env:kv --query 'value' -o tsv)
$sakMyOrg = $(az keyvault secret show --name "sakMyOrg" --vault-name $env:kv --query 'value' -o tsv)

# If Dev switch is added
# Note: Will be moved to KV
if($dev){
    $clientsecret = $env:dclientsecret
    $clientid = $env:dclientid
}

$username = [System.Text.Encoding]::UTF8.GetBytes($username)
$username =[Convert]::ToBase64String($username)
$password = [System.Text.Encoding]::UTF8.GetBytes($password)
$password =[Convert]::ToBase64String($password)
$cookie = [System.Text.Encoding]::UTF8.GetBytes($cookie)
$cookie =[Convert]::ToBase64String($cookie)
$lsusername = [System.Text.Encoding]::UTF8.GetBytes($lsusername)
$lsusername =[Convert]::ToBase64String($lsusername)
$lspassword = [System.Text.Encoding]::UTF8.GetBytes($lspassword)
$lspassword =[Convert]::ToBase64String($lspassword)

$elasticuser = Get-Content -Path  "$PSScriptRoot\global\elastic-user.yml"
$elasticuser = $elasticuser -replace "repusername" , $username
$elasticuser = $elasticuser -replace "reppassword" , $password
$elasticuser = $elasticuser -replace "repcookie" , $cookie
$elasticuser = $elasticuser -replace "replsusername" , $lsusername
$elasticuser = $elasticuser -replace "replspassword" , $lspassword

$elasticuser >> elastic-user.yml
kubectl apply -f elastic-user.yml
$valuesyml = Get-Content -Path  "$PSScriptRoot\opendistro-es-custom\values.yaml"
$valuesyml = $valuesyml -replace "repclientid" , $clientid
$valuesyml = $valuesyml -replace "repclientsecret" , $clientsecret
$valuesyml = $valuesyml -replace "repredirecturl" , $customername
# Dev Switch
if($dev){
    $valuesyml = $valuesyml -replace "<REPDEVTENANTID>" , $devTenant
}
$valuesyml > "$PSScriptRoot\opendistro-es-custom\values.yaml"
#sed -i "s/repclientid/$clientid/" "$PSScriptRoot\opendistro-es-custom\values.yaml" 
#sed -i "s/repclientsecret/$clientsecret/" "$PSScriptRoot\opendistro-es-custom\values.yaml" 
#sed -i "s/repredirecturl/$customername/" "$PSScriptRoot\opendistro-es-custom\values.yaml" 
$helminstall = helm ls -o json
$helminstall = ConvertFrom-Json $helminstall
if($helmInstall | ?{$_.name -eq $customername}){
    Write-Host "$customername already exist. Will Upgrade..."
    helm package $PSScriptRoot\opendistro-es-custom\.
    Write-Host "Creating $customername..."
    helm upgrade $customername .\opendistro-es-1.13.1.tgz
}
else{
    helm package $PSScriptRoot\opendistro-es-custom\.
    Write-Host "Creating $customername..."
    helm install $customername .\opendistro-es-1.13.1.tgz
}

#endregion

#region Master logstash 
if($secretsToDeploy | ?{$_ -contains "es-client-root-cert"}){
    Write-Warning "es-client-root-cert already exist"
}
else{
    Write-Information "Creating es-client-root-cert..." 
    kubectl create secret generic es-client-root-cert --from-file=es-client-root-ca.pem=root-ca.pem
}

$customer = $customername
$sacontainer = "lskey"
$ladns = "$customer-ls.example.com"
New-Item -Path $PSScriptRoot -Name $customer -ItemType "directory"
Set-Location -Path "$PSScriptRoot\$customer"
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/C=IN/ST=KA/L=Bangalore/O=MyOrg/OU=Test/CN=Logstash Root CA" -out ca.crt
openssl genrsa -out logstash.key 2048
sed -i "s/repdomain/$ladns/" "$PSScriptRoot\global\openssl.conf" 
openssl req -sha512 -new -key logstash.key -out logstash.csr -config "$PSScriptRoot\global\openssl.conf"
openssl x509 -days 3650 -req -sha512 -in logstash.csr -CAcreateserial -CA ca.crt -CAkey ca.key -out logstash.crt -extensions v3_req -extfile "$PSScriptRoot\global\openssl.conf"
mv logstash.key logstash.key.pem 
openssl pkcs8 -in logstash.key.pem -topk8 -nocrypt -out logstash.key
openssl genrsa -out beat.key 2048
openssl req -sha512 -new -key beat.key -out beat.csr -config "$PSScriptRoot\global\openssl-client.conf"
openssl x509 -days 3650 -req -sha512 -in beat.csr -CAcreateserial -CA ca.crt -CAkey ca.key -out beat.crt -extensions v3_req -extensions usr_cert  -extfile "$PSScriptRoot\global\openssl-client.conf"
sed -i "s/$ladns/repdomain/" "$PSScriptRoot\global\openssl.conf" 

if($secretsToDeploy | ?{$_ -contains "logstash-certs"}){Write-Warning "logstash-certs already exist" }
else{
    # Uploading certs to azure
    az storage blob upload-batch -d "$sacontainer\$customer" -s "$PSScriptRoot\$customer" --pattern * --account-name $env:saccount --account-key $sakey
    Write-Information "Creating logstash-certs..." 
    kubectl create secret generic logstash-certs --from-file=logstash.key=logstash.key --from-file=logstash.crt=logstash.crt --from-file=ca.crt=ca.crt
}

Set-Location -Path $PSScriptRoot

$helminstall = helm ls -o json
$helminstall = ConvertFrom-Json $helminstall
if($helmInstall | ?{$_.name -eq 'logstash'}){
    Write-Host "$customername already has logstash deployed will upgrade..."
    helm upgrade logstash $PSScriptRoot\logstash\ --set esmaster=$customer-elk-master:9200
}
else{
    helm install logstash $PSScriptRoot\logstash\ --set esmaster=$customer-elk-master:9200
}
# DNS Records
if(az network dns record-set cname show --resource-group $env:rg --zone-name search.example.com --name $("$customername") ){
Write-Output "CNAME for search.example.com already exist"
}
else{
Write-Output "Creating CNAME for search "
az network dns record-set cname set-record --resource-group $env:rg  --zone-name search.example.com --record-set-name $customername --cname "ingress001.search.example.com"
}
$lsipaddress = $null
$count = 0
Do {
    Write-Output "Creating external svc still creating ....."
    $services = kubectl get svc -o json
    $services = ($services | ConvertFrom-Json).items
    $service = $services | ?{$_.metadata.name -eq "logstash-logstash"}
    $lsipaddress = $service.status.loadbalancer.ingress.ip
    if($lsipaddress){
        if(az network dns record-set a show --resource-group $env:rg --zone-name search.example.com --name $("$customername-ls") ){
        Write-Output "DNS Record for Logstash already exist please update manually"
        }
        else{
        Write-Output "Creating DNS Record for Logstash"
        az network dns record-set a add-record -g $env:rg -z search.example.com -n $("$customername-ls") -a $lsipaddress	
        }
    }
    Start-Sleep -Seconds 10
    $count ++

} Until (($lsipaddress -ne $null) -or ($count -gt 5))

$ipaddresses = az network nsg rule show -g $env:rg --nsg-name $nsg -n $nsgRule --query destinationAddressPrefixes -o json
$ipaddresses = $ipaddresses | ConvertFrom-Json
$iplist = [System.Collections.ArrayList]@()
$ipaddresses | %{$iplist.Add($_)} | Out-Null
if($iplist -contains $lsipaddress)
{
Write-Output "IP Already added to NSG"
}
else
{
$singleIP = az network nsg rule show -g $env:rg --nsg-name $nsg -n $nsgRule --query destinationAddressPrefix -o json
if($singleIP){
    $iplist.Add($singleIP)
}    
$iplist.Add($lsipaddress)
$iplist
Write-Output "Adding Logstash ip to nsg"
az network nsg rule update -g $env:rg --nsg-name $nsg -n $nsgRule --destination-address-prefix $iplist 
}

#endregion

#region multiple logstash
if(Get-ChildItem -Path "$PSScriptRoot\logstash\application" -ErrorAction SilentlyContinue){
$lsapps = (Get-ChildItem -Path "$PSScriptRoot\logstash\application").Name
$original = Get-Content -Path  "$PSScriptRoot\logstash\values.yaml"
foreach($lsapp in $lsapps) {
    if(Test-Path "$PSScriptRoot\logstash\application\$lsapp\values.yaml"){
        $lsconfig = Get-Content -Path "$PSScriptRoot\logstash\application\$lsapp\values.yaml"
        $lsconfig = $lsconfig -replace "secretName: logstash-certs" , "secretName: $lsapp-logstash-certs"
        $lsconfig > $PSScriptRoot\logstash\values.yaml
    }
    else{
        $lsconfig = $original -replace "secretName: logstash-certs" , "secretName: $lsapp-logstash-certs"
        $lsconfig > $PSScriptRoot\logstash\values.yaml
    }
    $customer = $customername
    $sacontainer = "lskey"
    $ladns = "$lsapp-$customer-ls.search.example.com"
    New-Item -Path $PSScriptRoot -Name $lsapp -ItemType "directory"
    Set-Location -Path "$PSScriptRoot\$lsapp"
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/C=IN/ST=KA/L=Bangalore/O=MyOrg/OU=Test/CN=Logstash Root CA" -out ca.crt
    openssl genrsa -out logstash.key 2048
    sed -i "s/repdomain/$ladns/" "$PSScriptRoot\global\openssl.conf" 
    openssl req -sha512 -new -key logstash.key -out logstash.csr -config "$PSScriptRoot\global\openssl.conf"
    openssl x509 -days 3650 -req -sha512 -in logstash.csr -CAcreateserial -CA ca.crt -CAkey ca.key -out logstash.crt -extensions v3_req -extfile "$PSScriptRoot\global\openssl.conf"
    mv logstash.key logstash.key.pem 
    openssl pkcs8 -in logstash.key.pem -topk8 -nocrypt -out logstash.key
    openssl genrsa -out beat.key 2048
    openssl req -sha512 -new -key beat.key -out beat.csr -config "$PSScriptRoot\global\openssl-client.conf"
    openssl x509 -days 3650 -req -sha512 -in beat.csr -CAcreateserial -CA ca.crt -CAkey ca.key -out beat.crt -extensions v3_req -extensions usr_cert  -extfile "$PSScriptRoot\global\openssl-client.conf"
    sed -i "s/$ladns/repdomain/" "$PSScriptRoot\global\openssl.conf" 
    #openssl x509 -in logstash.crt -text -noout # Check if cert is created with valid name
    if($secretsToDeploy | ?{$_ -contains "$lsapp-logstash-certs"}){Write-Warning "$lsapp-logstash-certs already exist" }
    else{
        # Uploading certs to azure
        az storage blob upload-batch -d "$sacontainer\$customer\$lsapp" -s "$PSScriptRoot\$lsapp" --pattern * --account-name $env:saccount --account-key $sakey
        Write-Information "Creating logstash-certs..." 
        kubectl create secret generic "$lsapp-logstash-certs" --from-file=logstash.key=logstash.key --from-file=logstash.crt=logstash.crt --from-file=ca.crt=ca.crt
    }

    Set-Location -Path $PSScriptRoot

    $helminstall = helm ls -o json
    $helminstall = ConvertFrom-Json $helminstall
    if($helmInstall | ?{$_.name -eq "$lsapp"}){
        Write-Host "$lsapp for $customername already has logstash deployed will upgrade..."
        #Get-Content "$PSScriptRoot\logstash\values.yaml"
        helm upgrade $lsapp $PSScriptRoot\logstash\ --set esmaster=$customer-elk-master:9200
    }
    else{
        helm install $lsapp $PSScriptRoot\logstash\ --set esmaster=$customer-elk-master:9200
    }
    # DNS Records
    $lsipaddress = $null
    $count = 0
    Do {
        Write-Output "Creating external svc still creating ....."
        $services = kubectl get svc -o json
        $services = ($services | ConvertFrom-Json).items
        $service = $services | ?{$_.metadata.name -eq "$lsapp-logstash"}
        $lsipaddress = $service.status.loadbalancer.ingress.ip
        if($lsipaddress){
            if(az network dns record-set a show --resource-group $env:rg --zone-name search.example.com --name $("$lsapp-$customername-ls") ){
                Write-Output "DNS Record for Logstash $lsapp already exist please update manually"
            }
            else{
                Write-Output "Creating DNS Record for Logstash"
                az network dns record-set a add-record -g $env:rg -z search.example.com -n $("$lsapp-$customername-ls") -a $lsipaddress	
            }
        }
        Start-Sleep -Seconds 10
        $count ++

    } Until (($lsipaddress -ne $null) -or ($count -gt 5))

    $ipaddresses = az network nsg rule show -g $env:rg --nsg-name $nsg -n $nsgRule --query destinationAddressPrefixes -o json
    $ipaddresses = $ipaddresses | ConvertFrom-Json
    $iplist = [System.Collections.ArrayList]@()
    $ipaddresses | %{$iplist.Add($_)} | Out-Null
    if($iplist -contains $lsipaddress)
    {
        Write-Output "IP Already added to NSG"
    }
    else
    {
        $singleIP = az network nsg rule show -g $env:rg --nsg-name $nsg -n $nsgRule --query destinationAddressPrefix -o json
        if($singleIP){
            $iplist.Add($singleIP)
        }    
        $iplist.Add($lsipaddress)
        $iplist
        Write-Output "Adding Logstash ip to nsg"
        az network nsg rule update -g $env:rg --nsg-name $nsg -n $nsgRule --destination-address-prefix $iplist 
    }
}
}
else{
Write-Output "Multiple Logstash not needed"
}
#endregion

# Ingress
if(kubectl get ingress){
Write-Output "Ingress Already Deployed"
    if($ingressforce){
        Write-Output "Updating ingress as force is specified"
        sed -i "s/repcustomername/$customername/g" "$PSScriptRoot\global\ingress.yml" 
        kubectl apply -f "$PSScriptRoot\global\ingress.yml"
    }
}
else{
    sed -i "s/repcustomername/$customername/g" "$PSScriptRoot\global\ingress.yml" 
    kubectl apply -f "$PSScriptRoot\global\ingress.yml"
}