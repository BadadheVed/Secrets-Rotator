curl -s "https://api.cloudflare.com/client/v4/accounts/<acc_id>/tokens/permission_groups" \ 
  -H 'Authorization: Bearer <token>' \
  | python3 -c "import json,sys; [print(p['id'],'-',p['name']) for p in json.load(sys.stdin)['result'] if 'KV' in p['name']]"