# 简化版3DES
# 只支持ascii编码，一个字符用一个字节表示，8个比特
# 8个S盒都用了S2盒
# 不支持分组密码操作模式：ECB，CBC，CFB，OFB


# 初始置换IP表
IP_table = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

# 逆初始置换表
inverse_IP_table = [40, 8, 48, 16, 56, 24, 64, 32,
                    39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25]

# F函数中的扩展置换函数表
E_table = [32, 1, 2, 3, 4, 5,
           4, 5, 6, 7, 8, 9,
           8, 9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32, 1]

# S2盒
S2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]

# S盒简化成8个都是S2
S_table = [S2] * 8
# print(S_table)

# F函数中的P盒置换表
P_table = [16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25]

# 生成子密钥时的置换选择1表
PC1_table = [57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19, 11, 3, 60, 52, 44, 36,
             63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4]

# 生成子密钥时的置换选择2表
PC2_table = [14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
             23, 19, 12, 4, 26, 8,
             16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55,
             30, 40, 51, 45, 33, 48,
             44, 49, 39, 56, 34, 53,
             46, 42, 50, 36, 29, 32]


# 将字符串转为二进制比特
def str2bit(in_str):
    unicode_number = [ord(s) for s in in_str]
    # print(unicode_number)
    out_bit = []
    for i in range(len(unicode_number) * 8):
        # 每次左移一位取最后一位
        out_bit.append((unicode_number[int(i / 8)] >> (i % 8)) & 1)
    return out_bit

# 将二进制比特转为字符串
def bit2str(in_bit):
    unicode_number = []
    tmp = 0
    for i in range(len(in_bit)):
        tmp = tmp | (in_bit[i] << (i % 8))
        if i % 8 == 7:
            unicode_number.append(tmp)
            tmp = 0

    out_str = ''
    for i in range(len(unicode_number)):
        out_str = out_str + chr(unicode_number[i])

    return out_str

# 将加密后的字符二进制比特用16进制表示
def bit2hex(in_bit):
    unicode_number = []
    tmp = 0
    for i in range(len(in_bit)):
        tmp = tmp | (in_bit[i] << (i % 8))
        if i % 8 == 7:
            unicode_number.append(tmp)
            tmp = 0

    out_str = ' '.join([hex(n) for n in unicode_number])
    return out_str

# 将加密后的16进制表示的密文转成二进制比特
def hex2bit(in_hex):
    hexes = in_hex.split(' ')
    # 转成十六进制，去掉前缀0b，高位补0成8位
    hexes_bit_str = ''.join([bin(int(h, 16)).replace('0b', '').zfill(8) for h in hexes])

    # 为方便移位操作，二进制比特顺序反的，
    # 比如0x01存储顺序不是00000001，而是10000000
    # 这里调换和前面统一才行
    hexes_bit = [0] * 64
    for i in range(8):
        for j in range(8):
            hexes_bit[i * 8 + j] = int(hexes_bit_str[i * 8 + 7 - j])
    
    return hexes_bit


# 生成子密钥
def make_subkeys(init_key):
    init_key_bit = str2bit(init_key)

    # 置换选择1，密钥从64位到56位
    # 去掉了8，16，24，32，40，48，56，64上的奇偶校验位
    tmp_k = [0] * 56
    for i in range(56):
        tmp_k[i] = init_key_bit[PC1_table[i] - 1]

    subkeys = []
    # 迭代生成16个子密钥
    for i in range(16):
        # 在第1，2，9，16轮时
        # 循环左移只移动一个位置
        if (i == 0 or i == 1
            or i == 8 or i == 15):
            step = 1
        else:
            step = 2

        # 前28位和后28位各自进行循环左移
        for j in range(step):
            # 前28位循环左移一位
            tmp = tmp_k[0]
            for k in range(27):
                tmp_k[k] = tmp_k[k+1]
            tmp_k[27] = tmp

            # 后28位循环左移一位
            tmp = tmp_k[28]
            for k in range(28, 55):
                tmp_k[k] = tmp_k[k+1]
            tmp_k[55] = tmp

        sub_key = [0] * 48
        # 置换选择2，密钥从56位到48位
        for j in range(48):
            sub_key[j] = tmp_k[PC2_table[j] - 1]

        subkeys.append(sub_key)

    return subkeys


# 轮函数F
def F(R_bit, sub_key):
    # F函数中的扩展置换，32位到48位
    extend_R = [0] * 48
    for j in range(48):
        extend_R[j] = R_bit[E_table[j] - 1]

    # 扩展的结果和子密钥异或
    xor_with_subkey = [0] * 48
    for j in range(48):
        if sub_key[j] != extend_R[j]:
            xor_with_subkey[j] = 1

    # F函数中的s盒替换，48位到32位
    s_result = [0] * 32
    c = [1, 2, 4, 8]
    for j in range(8):
        a = [xor_with_subkey[j * 6 + k] for k in range(6)]
        # a1a6二进制为行号
        row = a[0] * c[1] + a[5] * c[0]
        # a2a3a4a5二进制为列号
        column = a[1] * c[3] + a[2] * c[2] + a[3] * c[1] + a[4] * c[0]

        s_picked = S_table[j][row * 16 + column]
        for k in range(4):
            s_result[j * 4 + k] = (s_picked >> k) & 1

    # F函数中的P盒置换
    p_result = [0] * 32
    for j in range(32):
        p_result[j] = s_result[P_table[j] - 1]

    return p_result


def DES(text, key, mode):
    text_bit = []
    # 子密钥使用顺序
    order_list = range(16)

    # 加密模式
    if mode == 'encode':
        text_bit = str2bit(text)
    # 解密模式
    else:
        text_bit = hex2bit(text)
        # 解密模式子密钥顺序相反
        order_list = range(15, -1, -1)

    subkeys = make_subkeys(key)
    output_bit = [0] * 64
    # 初始置换P
    initP_bit = [0] * 64
    for i in range(64):
        initP_bit[i] = text_bit[IP_table[i] - 1]

    # 分成左右两个部分开始16次迭代
    L_bit = initP_bit[:32]
    R_bit = initP_bit[32:]
    for i in order_list:
        F_output = F(R_bit, subkeys[i])

        # F函数的输出与左半部分L异或
        xor_with_L = [0] * 32
        for j in range(32):
            if F_output[j] != L_bit[j]:
                xor_with_L[j] = 1

        # 准备下一次迭代
        L_bit = R_bit
        R_bit = xor_with_L

    output = R_bit
    output.extend(L_bit)

    # 逆初始置换
    for i in range(64):
        output_bit[i] = output[inverse_IP_table[i] - 1]
    
    if mode == 'encode':
        # 加密后的比特对应的可能是无法显示的字符
        # 选择用十六进制来表示加密得到的密文
        return bit2hex(output_bit)
    else:
        return bit2str(output_bit)


# 将明文分成8个字符（64位）一组来加密，
# 最后不足的用空格补齐。
def run_DES(text, key, mode):
    tmp_result = []
    final_result = ''
    if mode == 'encode':
        length = len(text)
        text = text + (length % 8) * " "
        for i in range(int(len(text) / 8)):
            sub_text = text[i * 8 : i * 8 + 8]
            sub_result = DES(sub_text, key, mode)
            tmp_result.append(sub_result)

        final_result =  ' '.join(tmp_result)
    else:
        all_hex = text.split()
        length = len(all_hex)
        for i in range(int(length / 8)):
            sub_hex = ' '.join(all_hex[i * 8 : i * 8 + 8])
            sub_result = DES(sub_hex, key, mode)
            tmp_result.append(sub_result)

        final_result = ''.join(tmp_result)

    return final_result


def triple_DES(text, k1, k2, k3, mode, DES2_mode):
    result = ''
    if mode == 'encode':
        DES1 = run_DES(text, k1, 'encode')
        DES2 = run_DES(DES1, k2, DES2_mode)
        DES3 = run_DES(DES2, k3, 'encode')
        result = DES3
    else:
        DES3 = run_DES(text, k3, 'decode')
        DES2 = run_DES(DES3, k2, DES2_mode)
        DES1 = run_DES(DES2, k1, 'decode')
        result = DES1

    return result


if __name__ == '__main__':
    mode = input('please select a mode(encode or decode) for 3DES: ')
    while (not (mode == 'encode' or mode == 'decode')):
        mode = input('please select a mode(encode or decode): ')

    DES2_mode = input('please select a mode(encode or decode) for the middle DES in 3DES: ')
    while (not (DES2_mode == 'encode' or DES2_mode == 'decode')):
        mode = input('please select a mode(encode or decode) for the middle DES in 3DES: ')

    text = input('please input a text to {}: '.format(mode))

    k1 = input('please input k1(must be 8 characters): ')
    while len(k1) != 8:
        k1 = input('please input k1(must be 8 characters): ')

    k2 = input('please input k2(must be 8 characters): ')
    while len(k2) != 8:
        k2 = input('please input k2(must be 8 characters): ')

    k3 = input('please input k3(must be 8 characters): ')
    while len(k3) != 8:
        k3 = input('please input k3(must be 8 characters): ')

    print('{} result:'.format(mode), triple_DES(text, k1, k2, k3, mode, DES2_mode))
