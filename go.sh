COUNTER=0
while :
do
	COUNTER=$[$COUNTER +1]
	echo "---> ITERATION: $COUNTER "
	sleep 1
	rm -rf data
	mkdir data
	pyega3 -cf ega.json1 fetch EGAD00001003338 --output-dir data
done
