get_token()
{
 echo "Obtaining access token..."
 read token < <(curl -d "grant_type=password&client_id=f20cd2d3-682a-4568-a53e-4262ef54c8f4&client_secret=AMenuDLjVdVo4BSwi0QD54LL6NeVDEZRzEQUJ7hJOM3g4imDZBHHX0hNfKHPeQIGkskhtCmqAJtt_jm7EKq-rWw&username=ega-test-data@ebi.ac.uk&password=egarocks&scope=openid" -H "Content-Type: application/x-www-form-urlencoded" -k https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token | python3 -c "import sys, json; print(json.load(sys.stdin)[\"access_token\"])")
}

COUNTER=0
while :
do
	set +x						
	COUNTER=$[$COUNTER +1]
	echo "ITERATION: $COUNTER "
	sleep 1
	rm -rf ./data1
	mkdir ./data1
	get_token
	set -x			
	aria2c --file-allocation=none --log-level=warn -l- -ctrue -d"./data1" --check-certificate=false --header="Authorization: Bearer $token " http://hh-ega-kube-12.ebi.ac.uk:30000/elixir/data/files/EGAF00001753746
done