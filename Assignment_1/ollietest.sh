#!/bin/bash
#set -v
#set -x

upn="@chimpraceraim.onmicrosoft.com"

if [[ -f ~/user_creation.out ]]; then
	rm ~/user_creation.out
fi

if [[ -f ~/group_create.out ]]; then
        rm ~/group_create.out
fi

for (( i=1; i<21; i++)); do
	counter=1
	echo "Attempt $counter - Creating TestUser$i$upn" | tee -a  ~/user_creation.out
	checkUser=$(az ad user list --upn "testuser$i$upn" --query "[].objectId" --output tsv)
	if [[ ! -z $checkUser ]]; then
		echo "User testuser$i$upn already exists with oid $checkUser."
		continue;
	fi
	az ad user create --display-name "TestUser$i" --password "Abcd123$" --user-principal-name "testuser$i$upn" | tee -a ~/user_creation.out
	retVal=$?
	if [[ $retVal -eq 0 ]]; then
		echo "Attempt $counter - successfully created TestUser$i"
	fi
	while [[ $retVal -ne 0 && $counter < 3 ]]; do
		let "counter++"
		echo "Attempt $counter - Creating TestUser$i$upn" >> ~/user_creation.out
		az ad user create --display-name "TestUser$i" --password "Abcd123$" --user-principal-name "testuser$i$upn" | tee -a ~/user_creation.out
	done
	if [[ $counter -eq 3 ]]; then
		echo "Failed to create TestUser$i after 3 tries." | tee -a  ~/user_creation.out
	fi
done

echo 'Creating group "ollie Assignment Group"'
az ad group create --display-name "ollie Assignment Group" --mail-nickname "olliegroup" | tee -a ~/group_create.out
groupOid=$(az ad group list --display-name "ollie Assignment Group" --query "[].objectId" --output tsv)
#echo $groupOid
for (( i=1; i<21; i++)); do
	attempt=0
	username="testuser$i$upn"
	userOid=$(az ad user list --upn $username --query "[].objectId" --output tsv)
	while [[ $attempt -le 3 ]]; do
		let "attempt++"
		az ad group member add --group $groupOid  --member-id $userOid
		retVal=$?
		if [[ $retVal -eq 0 ]]; then
			echo "Attempt #$attempt - $username - `date +"%b %d %Y - %H:%M:%S"` - Success" | tee -a ~/group_create.out
			continue;
		else
			echo "Attempt #$attempt - $username - `date +"%b %d %Y - %H:%M:%S"` - Failed " | tee -a ~/group_create.out
		fi
	done
done

echo "User Logs Created: ~/user_creation.out"
echo "Group Logs: ~/group_create.out"
