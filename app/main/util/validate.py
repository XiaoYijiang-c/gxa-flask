import re
def validate_mobile(Phone):
    hmd = [134,135,136,137,138,139,150,151,152,157,158,159,182,183,184,187,188,147,178,
         130,131,132,155,156,185,186,145,176,179,133,153,180,181,189,177]#列表
    if Phone.isnumeric():#判断Phone是否全部都是数字字符
        if len(Phone) == 11:#判断手机号是否为11位
            if int(Phone[0:3]) in hmd:#如果输入的手机号前三位数字在列表中，则输出"是一个有效号码"
                return True, None
            else:#如果输入的手机号前三位数字不在列表中，则输出"不是有效运营商网段"
                return False, {'error': (Phone, "不是有效运营商网段")}
                # raise ValueError({'error': (Phone, "不是有效运营商网段")})
        else:#如果手机号不是11位，则输出"号码位数不对！"
            return False, {'error': (Phone, "号码位数不对！")}
            # raise ValueError({'error': (Phone, "号码位数不对！")})
    else:#如果输入的手机号字符串不全是数字，则输出"号码必须全是数字"
        return False, {'error': (Phone, "手机号码必须全是数字")}
        # raise ValueError({'error': (Phone, "手机号码必须全是数字")})
def validate_email(value):
    print('进来验证邮箱')
    if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
        return False, {'error':"Invalid email address"}
        # raise ValueError("Invalid email address")
    else:
        return True, None

def str_to_int_id(value):
    res = value.isdecimal()
    if not res:
        return False, {'error': '输入编号不是数字'}
        # raise ValueError({'error': '输入编号不是数字'})
    return True, int(value)

def validaet_input_sysuser(data):
    res_email, mesg_email = validate_email(data['email'])
    res_mobile, mesg_mobile = validate_mobile(data['mobile'])
    if res_mobile and res_email:
        return True, None
    else:
        return False, {'error_email': mesg_email, 'error_mobile': mesg_mobile}

def validate_input_taguser(data):
    res_email, mesg_email = validate_email(data['email'])
    res_mobile, mesg_mobile = validate_mobile(data['mobile'])
    res_orgid, mesg_orgid = str_to_int_id(data['orgid'])
    err = ''
    if 'representativeID' in data.keys():
        res_representativeID, mesg_representativeID = str_to_int_id(data['representativeID'])
        if res_representativeID:
            data['representativeID'] = mesg_representativeID
        else:
            err = mesg_representativeID

    if res_email and res_mobile and res_orgid:
        data['orgid'] = mesg_orgid
        return True, data
    else:
        if not err:
            return False, {'error_email': mesg_email, 'error_mobile': mesg_mobile, 'mesg_orgid': mesg_orgid, 'mesg_representativeID': mesg_representativeID}
        return False, {'error_email': mesg_email, 'error_mobile': mesg_mobile, 'mesg_orgid': mesg_orgid}
