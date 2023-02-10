# DPcheck
Default password checker 

## Docker usage
docker build -t dpcheck . 
docker run -d --name dpcheck-cont -p 8000:80 dpcheck 

## OpenAPI url
http://127.0.0.1:8000/docs 

## How to use
Send post request to http://127.0.0.1:8000/checkDP with json paylod: 

e.g. 
`code`
[
	{
		"mac": "66:77:88:99:00",
		"ip": "192.168.1.1",
		"vendor": "test",
		"model": "t1234",
		"function": "router"
	},
	{
		"mac": "11:22:33:44:55",
		"ip": "192.168.1.2",
		"vendor": "test2",
		"model": "t5678",
		"function": "IP phone"
	}
]
`code`
The output will be all asset with default password 

![image](https://user-images.githubusercontent.com/36591853/218095103-3714613c-bfa8-4056-b584-e877fe38163e.png)


