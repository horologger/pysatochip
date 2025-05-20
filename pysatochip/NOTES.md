.venvZilla:pysatochip i830671$ 

 export PYSATOCHIP_PIN='qqqq'

python3 satochip_cli.py satochip-sign-message --path "m/84'/0'/0'/0/0" --message 'hello'

--path "m/84'/0'/0'/0/0" = bc1qpedagg2m50qhf64v4ptd36xd53lhm30w956wew First address

python3 satochip_cli.py satochip-sign-message --message 'hello'


python3 satochip_cli.py common-verify-pin
SentSELECT APDU for Satochip applet (AID: 53 61 74 6F 43 68 69 70)
DEBUG: Sending APDU: ['0x0', '0xa4', '0x4', '0x0', '0x8', '0x53', '0x61', '0x74', '0x6f'] # Select Satochip applet
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x3c', '0x0', '0x0'] # Get Status
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x81', '0x0', '0x0', '0x41', '0x4', '0xf4', '0x66', '0x92'] # Init Secure Channel
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
Enter your PIN:
Correct Pin Verified

.venvZilla:pysatochip i830671$ python3 satochip_cli.py satochip-sign-message --message 'hello'
DEBUG: CardConnection.T0_protocol = 1
DEBUG: CardConnection.T1_protocol = 2
DEBUG: CardConnection.RAW_protocol = 65536
DEBUG: Trying T0 protocol...
DEBUG: Failed to connect using T0 protocol: Unable to connect with protocol: T0. Card protocol mismatch.: Card protocol mismatch. (0x8010000F)
DEBUG: Trying T1 protocol...
DEBUG: Successfully connected using T1 protocol
DEBUG: Sending APDU: ['0x0', '0xa4', '0x4', '0x0', '0x8', '0x53', '0x61', '0x74', '0x6f'] # Select Satochip applet
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x3c', '0x0', '0x0'] # Get Status
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x81', '0x0', '0x0', '0x41', '0x4', '0x3a', '0xac', '0x52']
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
Enter your PIN:
DEBUG: Sending APDU: ['0xb0', '0x82', '0x0', '0x0', '0x38', '0xeb', '0x2a', '0x3c', '0xf3'] # Verify PIN
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x82', '0x0', '0x0', '0xc8', '0x59', '0xc5', '0xb3', '0xfd'] # Sign Message
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x82', '0x0', '0x0', '0x48', '0xbd', '0x24', '0x28', '0x8e']
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x82', '0x0', '0x0', '0x38', '0x15', '0xb8', '0x34', '0xc9']
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
DEBUG: Sending APDU: ['0xb0', '0x82', '0x0', '0x0', '0x38', '0xd1', '0x4a', '0x88', '0xd0'] # Sign Message
DEBUG: APDUResponse: SW1: 0x90, SW2: 0x0
Signature (Base64): HyGiaG85aAVQzxs/mI7OzwudmYO/8HubhVb1zo3UbJYM3WH42mm2G0ux6zd3omGdrmKNYZs17N9rqDsWQvMR3vs=
