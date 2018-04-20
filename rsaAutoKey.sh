#!/bin/bash
#1.生成带签名的秘钥
#2. 利用自动生成的秘钥加解密内容

CMD=$1
help(){
    echo "帮助语法:"
    echo "      gen keyname"
    echo "      enc publicKey encpytContent"
    echo "      dec privateKey decpytContent"
}

SignPrivateKey(){
    file=$1
    echo "-----BEGIN RSA PRIVATE KEY-----"  > ${file}
    echo "MIICWwIBAAKBgQC9kLp9DWCjLkvgmLpxbeFT6v0Ysa1LP3G8CoSwRusa/CPvl6jN">> ${file}
    echo "lQ/3GkMUmxvLgwJHcXQ0F/tD4y4RpF0LRe2bdy55E4Xmk7PNakJtsxQgjHD7oLFF">> ${file}
    echo "6WLaA6LCetbd3lMJZ0locwJKjeJa34jx+dNYKhjR3EvW4dcvP8kx99K27wIDAQAB">> ${file}
    echo "AoGAfCAljLbSvWcWNiWrh5R8g/eN7LqDD4+miIuWoNp/HfdWDI+Q77SYdKQUooyC">> ${file}
    echo "IbtSJbfLcET3uVcrlk+6wSPz1cUGWFmnTplg3KhvLzCLLT08fsm2MJCI70om1a7z">> ${file}
    echo "GNoxDJIBxtjr/kPFqUprkzXwdrrJcSGNmC1VOx2XBk0mFoECQQDj4tjyguwX++eG">> ${file}
    echo "tKIRBjMAFZCidoK7horSs83+l7vaYBYH7Hg8dn6y7w5jVOlSmYSi64kA6Epr86kX">> ${file}
    echo "ksbwyK7BAkEA1POgFMvU0ZDiDqZn1jocMkvxcY/S27fD78VYouwx5N56ccC2kdaF">> ${file}
    echo "EDquqO2HcS+SzmMBQ6ym+MzuB8t995SBrwJAag/cdRJmG8uMOG+9tjqyZemjhVmv">> ${file}
    echo "AuRdnC8/Qq0QK1TpLArs8wcbdOA6TBTq+xykVMdW3ms+p/uhyWzw1oQwgQJAElYD">> ${file}
    echo "46aFZaIPBOnpKPYJ9X66hGe45ThWg6+/aQ/jX+yUKHVKgxYwkOwsm9kP/3v0LRcz">> ${file}
    echo "Rat5GRU0LbGk4AuGewJATVT8ZL9FEUqrtR+QrA0FTHjcVViFw6xV/5CVs1cU6+dp">> ${file}
    echo "XL716Vsr50X0IKi0dVGbZ6TJLm4pFqY7QgJa3Ku88g==" >> ${file}
    echo "-----END RSA PRIVATE KEY-----" >> ${file}
}


# 生成公私钥对
# 输入两个参数 $1 私钥名；$2 公钥名
generatePairKeys(){
    TMP_KEY_FILE=/tmp/rsa_pri_.$$.pem
    RSA_PRI_NAME=${1}
    RSA_PUB_NAME=${2}
    openssl genrsa -out ${TMP_KEY_FILE} 1024
    openssl pkcs8 -topk8 -in ${TMP_KEY_FILE} -out ${RSA_PRI_NAME} -nocrypt
    openssl rsa -in ${RSA_PRI_NAME} -out ${RSA_PUB_NAME} -pubout
    rm ${TMP_KEY_FILE}
}

# 对给定文件进行签名，签名放在行首
# 输入两个参数 $1 签名私钥名；$2 待签名文件   $3 最终文件名
signFile(){
    SING_PRI_KEY=$1
    TARGE_FILE=$2
    SIGN_FILE=sign_${TARGE_FILE}
    if [[ $3 != "" ]]; then
        SIGN_FILE=$3
    fi
    SIGNSTR=`openssl dgst  -sha256 -sign ${SING_PRI_KEY}  -keyform PEM  ${TARGE_FILE} | base64`
    echo ${SIGNSTR}| sed -e 's/[ ][ ]*//g' > ${SIGN_FILE}
    cat ${TARGE_FILE} >> ${SIGN_FILE}
    echo "signed file ${SIGN_FILE} geneated"
}

# 生成带签名的公私钥对
# 输入两个参数 $1 签名私钥名；$2 生成秘钥名称
genPairsKeysAndSign(){
    SING_PRI_KEY=$1
    RSA_FILE=$2

    RSA_PRI_NAME=/tmp/${RSA_FILE}_rsa_private_key.pem
    RSA_PUB_NAME=/tmp/${RSA_FILE}_rsa_public_key.pem
    generatePairKeys ${RSA_PRI_NAME} ${RSA_PUB_NAME}

    SIGN_PRI_NAME=${RSA_FILE}_sign_rsa_private_key.pem
    SIGN_PUB_NAME=${RSA_FILE}_sign_rsa_public_key.pem

    signFile ${SING_PRI_KEY}  ${RSA_PRI_NAME}   ${SIGN_PRI_NAME}
    signFile ${SING_PRI_KEY}  ${RSA_PUB_NAME}   ${SIGN_PUB_NAME}

}

# $1 秘钥  ,$2 原文
encrypt(){
    TMPFILE=/tmp/encrypt$$
    echo $2 > ${TMPFILE}
    ENCCONTENT=`openssl rsautl -encrypt -in ${TMPFILE} -inkey $1  -pubin |base64`
    echo "加密结果为:"
    echo ${ENCCONTENT} | sed -e 's/[ ][ ]*//g'
    rm ${TMPFILE}
}

# $1 秘钥  ,$2 密文
decrypt(){
    TMPFILE=/tmp/decrypt$$
    osversion=`uname -s`
    if [[ ${osversion} == 'Linux' ]]; then
        echo $2 | base64 -d >> ${TMPFILE}
    else
        # mac os
    #elif [[ ${osversion} == 'Darwin' ]]; then
        echo $2 | base64 -D >> ${TMPFILE}
    fi
    DECCONTENT=`openssl rsautl -decrypt -in ${TMPFILE} -inkey $1`
    echo '解密内容:'
    echo ${DECCONTENT}
    rm ${TMPFILE}
}

if [[ $# -eq 2 ]]; then
    if [[ ${CMD} != "gen" ]]; then
        help
        exit 1
    fi
elif [[ $# -ne 3 ]]; then
    help
    exit 1
fi



if [[ ${CMD} == "gen" ]]; then
    SIGN_KEY_FILE=/tmp/sign_private_key$$.pem
    SignPrivateKey ${SIGN_KEY_FILE}
    genPairsKeysAndSign ${SIGN_KEY_FILE}  $2
    rm ${SIGN_KEY_FILE}
elif [[ ${CMD} == "enc" ]]; then
    TMP_KEY=/tmp/tmpkey$$
    sed 1d $2 > ${TMP_KEY}
    encrypt ${TMP_KEY} $3
    rm ${TMP_KEY}
elif [[ ${CMD} == "dec" ]]; then
    TMP_KEY=/tmp/tmpkey$$
    sed 1d $2 > ${TMP_KEY}
    decrypt ${TMP_KEY} $3
    rm ${TMP_KEY}
else
    help
fi
