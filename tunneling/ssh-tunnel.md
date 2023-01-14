#Simple ssh tunneling instructions
export host_key = sample-key.pem
export dest_host = ""
export source_host = ""

sudo ssh -vv -N -L 8888:127.0.0.1:3128 -i ~/.ssh/sample-key ubuntu@$dest_host
$source_host
