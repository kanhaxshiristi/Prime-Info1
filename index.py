from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime
import json

app = Flask(__name__)

# FF INFO ACC 
DEFAULT_UID = "3997271134="
DEFAULT_PASS = "BF9195F9C89E650DA3FB8B92795B6031E86BA2D8226B2C313252CC3566B46037"
JWT_GEN_URL = "https://dev-jwt-api.onrender.com/token?"

# GET JWT
def get_jwt():
    try:
        params = {
            'uid': DEFAULT_UID,
            'password': DEFAULT_PASS
        }
        response = requests.get(JWT_GEN_URL, params=params)
        if response.status_code == 200:
            jwt_data = response.json()
            return jwt_data.get("token")
        return None
    except Exception as e:
        return None
        
def format_boolean(value):
    return True if value == 1 else False
        
def format_timestamp(timestamp):
    if not timestamp or not str(timestamp).isdigit():
        return "N/A"
    return datetime.fromtimestamp(int(timestamp)).strftime('%d %B %Y %H:%M:%S')
        
#DONT EDIT
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == "string":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
            result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)

@app.route('/info', methods=['GET'])
def get_player_info():
    try:
        player_id = request.args.get('id')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        token = get_jwt()
        if not token:
            return jsonify({
                "status": "error",
                "message": "Failed to generate JWT token",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)

            try:
                player_data = {
                "Accountbasicinfo": {
                "AccountName": parsed_data.get("1", {}).get("data", {}).get("3", {}).get("data", "Unknown"),
                "AccountId": player_id,
                "AccountLikes": parsed_data.get("1", {}).get("data", {}).get("21", {}).get("data", "N/A"),
                "AccountLevel": parsed_data.get("1", {}).get("data", {}).get("6", {}).get("data", "N/A"),
                "AccountEXP": parsed_data.get("1", {}).get("data", {}).get("7", {}).get("data", "N/A"),
                "AccountBPID": parsed_data.get("1", {}).get("data", {}).get("19", {}).get("data", "N/A"),
                "AccountSeasonId": parsed_data.get("1", {}).get("data", {}).get("20", {}).get("data", "N/A"),
               "AccountLastLogin": format_timestamp(parsed_data.get("1", {}).get("data", {}).get("24", {}).get("data", "N/A")),
               "CsMaxRank": parsed_data.get("1", {}).get("data", {}).get("36", {}).get("data", "N/A"),
               "AccountType": parsed_data.get("1", {}).get("data", {}).get("45", {}).get("data", 1),
               "Title": parsed_data.get("1", {}).get("data", {}).get("48", {}).get("data", "N/A"),
               "ShowBrRank": format_boolean(parsed_data.get("1", {}).get("data", {}).get("52", {}).get("data", "N/A")),
               "ShowCsRank": format_boolean(parsed_data.get("1", {}).get("data", {}).get("53", {}).get("data", "N/A")),
               "ReleaseVersion": parsed_data.get("1", {}).get("data", {}).get("50", {}).get("data", "N/A"),
                "BrRankPoint": parsed_data.get("1", {}).get("data", {}).get("15", {}).get("data", "N/A"),
                "BrMaxRank": parsed_data.get("1", {}).get("data", {}).get("14", {}).get("data", "N/A"),
                "EquippedWeapon": parsed_data.get("1", {}).get("data", {}).get("32", {}).get("data", "N/A"),
                "AccountAvatarId": parsed_data.get("1", {}).get("data", {}).get("12", {}).get("data", "Default"),
                "AccountBannerId": parsed_data.get("1", {}).get("data", {}).get("11", {}).get("data", "Defalut"),
                "AccountRegion": parsed_data.get("1", {}).get("data", {}).get("5", {}).get("data", "Unknown"),
                "AccountBPBadges": parsed_data.get("1", {}).get("data", {}).get("18", {}).get("data", 0),
                "AccountCreateTime": format_timestamp(parsed_data.get("1", {}).get("data", {}).get("44", {}).get("data", "Not Found")),
                    }
                }
                
                try:
                    player_data["petInfo"] = {
    "id": parsed_data.get("8", {}).get("data", {}).get("1", {}).get("data", "Not Found"),
    "level": parsed_data.get("8", {}).get("data", {}).get("3", {}).get("data", "Not Found"),
    "exp": parsed_data.get("8", {}).get("data", {}).get("4", {}).get("data", "Not Found"),
    "selectedSkillId": parsed_data.get("8", {}).get("data", {}).get("9", {}).get("data", "Not Found"),
    "skinId": parsed_data.get("8", {}).get("data", {}).get("6", {}).get("data", "Not Found"),
    "name": parsed_data.get("8", {}).get("data", {}).get("2", {}).get("data", "Not Found"),
}
                except:
                    player_data["name"] = None

                try:
                    player_data["GuildInfo"] = {
    "GuildName": parsed_data.get("6", {}).get("data", {}).get("2", {}).get("data", "Not Found"),
    "GuildID": parsed_data.get("6", {}).get("data", {}).get("1", {}).get("data", "Not Found"),
    "GuildLevel": parsed_data.get("6", {}).get("data", {}).get("4", {}).get("data", "Not Found"),
    "GuildMembers": parsed_data.get("6", {}).get("data", {}).get("6", {}).get("data", "Not Found"),
    "GuildCapacity": parsed_data.get("6", {}).get("data", {}).get("5", {}).get("data", "Not Found"),
    "GuildOwner": parsed_data.get("6", {}).get("data", {}).get("3", {}).get("data", "Not Found"),
}

                    player_data["captainbasicinfo"] = {
    "accountid": parsed_data.get("6", {}).get("data", {}).get("3", {}).get("data", "Not Found"),
    "nickname": parsed_data.get("7", {}).get("data", {}).get("3", {}).get("data", "Not Found"),
    "level": parsed_data.get("7", {}).get("data", {}).get("6", {}).get("data", "Not Found"),
    "region": parsed_data.get("7", {}).get("data", {}).get("5", {}).get("data", "Not Found"),
    "exp": parsed_data.get("7", {}).get("data", {}).get("7", {}).get("data", "Not Found"),
    "rank": parsed_data.get("7", {}).get("data", {}).get("14", {}).get("data", "Not Found"),
    "rankingPoints": parsed_data.get("7", {}).get("data", {}).get("15", {}).get("data", "Not Found"),
    "badgeId": parsed_data.get("7", {}).get("data", {}).get("19", {}).get("data", "Not Found"),
    "seasonId": parsed_data.get("7", {}).get("data", {}).get("20", {}).get("data", "Not Found"),
    "title": parsed_data.get("7", {}).get("data", {}).get("48", {}).get("data", "Not Found"),
    "releaseVersion": parsed_data.get("7", {}).get("data", {}).get("50", {}).get("data", "Not Found"),
    "showBrRank": format_boolean(parsed_data.get("1", {}).get("data", {}).get("52", {}).get("data", 0)),
    "showCsRank": format_boolean(parsed_data.get("1", {}).get("data", {}).get("53", {}).get("data", 0)),
    "lastLoginAt": format_timestamp(parsed_data.get("7", {}).get("data", {}).get("24", {}).get("data", 0)),
    "csRank": parsed_data.get("7", {}).get("data", {}).get("30", {}).get("data", "Not Found"),
    "csRankingPoints": parsed_data.get("7", {}).get("data", {}).get("31", {}).get("data", "Not Found"),
    "maxRank": parsed_data.get("7", {}).get("data", {}).get("35", {}).get("data", "Not Found"),
    "bannerId": parsed_data.get("7", {}).get("data", {}).get("11", {}).get("data", "Not Found"),
    "headpic": parsed_data.get("7", {}).get("data", {}).get("12", {}).get("data", "Not Found"),
    "badgeCnt": parsed_data.get("7", {}).get("data", {}).get("18", {}).get("data", "Not Found"),
    "liked": parsed_data.get("7", {}).get("data", {}).get("21", {}).get("data", "Not Found"),
    "createAt": format_timestamp(parsed_data.get("7", {}).get("data", {}).get("44", {}).get("data", 0)),
}



                    player_data["socialinfo"] = {
    "AccountSignature": parsed_data.get("9", {}).get("data", {}).get("9", {}).get("data", "Not Found")
}

                    player_data["creditScoreInfo"] = {
    "creditScore": parsed_data.get("11", {}).get("data", {}).get("1", {}).get("data", "Not Found"),
    "rewardState": parsed_data.get("11", {}).get("data", {}).get("3", {}).get("data", "Not Found"),  
    "periodicSummaryStartTime": parsed_data.get("11", {}).get("data", {}).get("8", {}).get("data", "Not Found"),
    "periodicSummaryEndTime": parsed_data.get("11", {}).get("data", {}).get("9", {}).get("data", "Not Found")
}

                    player_data["ProfileInfo"] = {
    "EquippedOutfit": parsed_data.get("2", {}).get("data", {}).get("4", {}).get("data", "N/A"),
    "EquippedSkills": parsed_data.get("2", {}).get("data", {}).get("5", {}).get("data", "N/A"),
}
                except:
                    player_data["clan"] = None

                return jsonify({
                    "status": "success",
                    "AccountInfo": player_data,
                })

            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Failed to parse player information: {str(e)}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }), 500

        return jsonify({
            "status": "error",
            "message": f"API request failed with status code: {response.status_code}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)