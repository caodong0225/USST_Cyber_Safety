import re
import string
from crypto import crypt

ENG_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074
}


def filter_text(ciphertext):
    """预处理：去除非字母字符，转为大写"""
    return re.sub(r'[^a-zA-Z]', '', ciphertext).lower()


def cal_fre(text: str):
    res = {}
    for c in string.ascii_lowercase:
        res[c] = text.count(c)
    return res


def _calc_confidence(freq, text_length: int) -> float:
    confidence = 0.0
    for c in string.ascii_lowercase:
        eng_freq = ENG_FREQ[c]  # 标准英语频率（如 e=0.127）
        decrypted_freq = freq.get(c, 0) / text_length  # 解密文本的频率
        confidence += (eng_freq - decrypted_freq) ** 2  # 平方差累加
    return 1 / (1 + confidence / 26)  # 归一化为置信度


def brute_force_decrypt(cipher: str, key_length: int, top_n: int = 3):
    cipher = filter_text(cipher.lower())

    # 按字符长度分组切片
    slices = ['' for _ in range(key_length)]
    for i, char in enumerate(cipher):
        slices[i % key_length] += char
    key_possibilities = []

    for s in slices:
        possibilities = {}
        for shift in range(26):
            key_char = chr(ord('a') + shift)
            decrypted_slice = crypt(s, key_char, 1)
            possibilities[key_char] = _calc_confidence(cal_fre(decrypted_slice), len(s))
        sorted_possibilities = sorted(possibilities.items(), key=lambda x: x[1], reverse=True)
        key_possibilities.append(sorted_possibilities[:top_n])
    return key_possibilities


ciphertext = """
    g vjganxsymda ux ylt vtvjttajwsgt bl udfteyhfgt
oe btlc ckjwc qnxdta
vbbwwrbrtlx su gnw nrshylwmpy cgwps, lum bipee ynecgy gk jaryz frs fzwjp, x puej jgbs udfteyhfgt, gnw sil uuej su zofi. sc okzfpu bl lmi uhzmwi, x nyc dsj bl lmi enyl ys argnj yh nrgsi. nba swi cbz ojprbsw fqdam mx. cdh nsai cb ygaigroysxn jnwwi lr msylte.
cw mekr tg jptpzwi kdikjsqtaz, ftv pek oj pxxkdd xd ugnj scr, yg n esqxwxw nba onxw au ywipgkj fyiuujnxn gnss xwnz onxw jnahl avhwwxn vzkjpu nrofch fvwfoh. v jwhppek lmi vyutfp hbiafp hcguj at nxw gyxyjask ib hw seihxsqpn vtvjttajwsx ds zzj xnegfsmtf egz wtrq lt mbcukj sc hy. qty wnbw ss bbxsq vxtnl ys ghrw zw cbx vt cdh vgxwtfy ssc brzzthh bl wsjdeiwricg cw mekr zjzi grgktr ib lwfv.
vbbwwrbrtlx hteonj xwroj oyhg vgbigf ljtq iuk utrhrtl tj iuk ytztetwi. cdh nsai crolmig fudngxgkv ssg ekujmkrj gzvh. jk vnh cbz aszxgk qty. nba vt rdg qfta jf, tgw hd lum prdj umw aderv. hcqrxkuerr jgjw cbz dni lvzznr nbaj gsgqkjx. hd aul ylxaq lmei lum hec oaaqh xg, gk yldhmz nx lrxw f tjorah gdaylwyrgogs tgbpwhx. nba ufrcbz. ay mh nt shx ds tsyygr gfi mi txgbw xgywqj iuxgzkw baj hsaykuymkr guymday.
qty wnbw ssi rtyfktq of tyg txwfx paj yfxwrxask rbtnjvhnzatr, cbx vnh nba uwipgk lmi lrgdyl ds umw qpeqwytaniwx. cdh jg ssi xtgb sje imqxjek, gzv tgnahw, de zzj ycjxayxta igiih gnsy eaeksic eeunnht baj xsrvkld qdek gwhte zzfr rbadi ft bhlfmcrj td ecl ux dsje oeushvzatrh.
lum hppvs lmigr gjj tgbhdjqh nsgsk jf zzfx nba fjis gu ktpkr. egz yhr zznw rygar eh nt wcgjfk lt mcigvj sje vjjgxailx. qpae gk xwryw uvdorwrw sbt'l jbxfz. omigr zzjvt nxw wipy igsjavilx, awrxw yltek swi leuflw, lr caqp xqkfymul zzjq paj sihgryk yltz hq tyg zkssw. lr gjj jdesask dhx gbr hbiafp rbtlwerg. zznw vbbwwrpaiw bmay gjnwt niutvsvty ys iuk utrsvzatrh bl gzv lbxdi, rdg egzvh. baj bsgyj ax hxslwwicg.
iqgigfvshi rbtknwif ux yvpayshxxbtk, wianzatrhuohx, ecq zztyvuz aywtyl, swvplkv qmzr g kyecqofl apik as xwr cwg su baj hsbzafngpgogsw. dhxk nw p jujqh iugl nw qbzz jzteeomigr gfi rdjnwwi, qhz ay mh aul bltek tthxry dnzt.
jk swi reksymct g otvaq zzfx pyr efc tazww axgngzx eeonnpttk gw tgrpmimrr guhsgqkv gc gniw, jgdaueng ebcww, qxyolfvn sujhi, de ylfxxbt gk fxezz.
bi pek uwipgofl e lbxdi awrxw frnbtw, frnjnwwi bne wctgryk mmh bx zjv qrrajjh, au efxirx zta hvtyzppe, cayldhz xjeg bl tjmct igjvrrj asxd fodjrrr uj hscsujrmil.
egzv armsq gdaiwuxh bl hwserxld, imcxwxwxbt, aiicgold, qdikejri, ntv hscgkpy hd aul fteye lt yh. gnwd egr gdq fpfkv tr bnzljv, paj lmigr ok ss bnzljv wrxw.
tyg vjwsxxgowx lpik ft fdqowx, wd, htdnot lum, bi rntftx dozsnr dejww fn cnqxmrnr utigpogs. at okdnikr zzfx ueue jxwvik, jravmzyicrj kjpu-vtljvtfz, ssh iuk utqbbtojea, baj lskrxffrrr caqp tzkjli. dhx aiicgolnih zgq gi svylwmqhzwi ereukx qpae gk cdhx bzvxfjahxxbtk. ylt btdd ppj zzfx pyr gzv rbtkymihkfy gjyzmwih jumqh vrtwweaye jjgdttaei xf zzj kdyjws vjyk. oj ldck oj axyr tj eqyk lt fjvrv tyg cgjymrhrsw wdyalnscf uf ylpg hsxmh. oal bi rntftx ppiwux iuk ktpjgogsw nba swi pgzwrtivty ys xzvgxi.
xa zzj ycvzwi winzwx, cdh nsai ibjsd ggrgljh p ygo, ylt gkdjgdzsmsmrnzatrh ekxtvb nil, blxpn jjtjqosyih lumw sla igswivzmymda gfi mcfadyw iuk vwipzy gk ntslwwwda, csxlxamltr, bvrd, resvygs, htguizikvrdj, ecq hjfrsrok. yltfk vwipzy ezwi auo gi qbxf frtj of zw.
nba swi irxjnjxrj gk cdhx gbr ruodivta, yasgt gnwd egr tsymkry as e lbxdi awrxw dsj jodq eajgqx ft vsenkgntlx. ftpgmxi nba xjeg gnwr, cdh kfyvjfz qtyg oajjejpxshmtf cayl iuk hfvtazsq vtfvgswxoodnxxry qty pek lts rbcswhal zg hscsxgsx nbajxiaikk. nr dhx otvaq, gdq xwr ywsxxzkfyw paj wctgryknscf ux mybntayc, ueue ylt qktfwxam lt xwr gfliavi, swi enxlx su n ywfqaryk bldyk, lmi vyutfp rbtnjvhnzatr ds hayw. lr issrdg ywuegnzw ylt noj ylpg iztotf ljtq iuk snv jcuf blxpn onrvf hwfx.
xa iznrp, tkjrecl, ljfrrr, xmxwxn, yaskpcujj, minrq frs gnw zrxgkv xxpgkk, dsj nxw yvnvty ys lnxv tju gnw amghy gk pxokjyc ql kjjgivty lypej htwif gl ylt sxgsxxrxk tj rlhwwweniw. yltfk efc zrkh tyi gnw hscggynsc suj f wbnrd ymbr, hmy xwre onpa aul bsgx of f aderv ylpg caqp hbuf gi qygfpiirj as fxg-hwfvxam ejhxn.
egzv xaijjehvtyqc doygqiir ofksgzglnsc vtvzwieowx adhrv uigcklzeir zzjqhrrnjw ql vjttdfofl ppjy, as ebrxahe paj wqwtjnwwi, iugl hppvs lt sla yhjiru olxias zzwsjtngzx iuk otvaq. zzjwt ygox adhrv iirygjj msrgk ys qr gftxwrx ashjfzjnea cxgiyrg, tg rsgr tggpt gnss txt ojtr. xa umw aderv, blpgknjv iuk zzqpa sash bne uwipgk ufr qr xwuvdqaujh paj vnwieotzxtq ofkmcvzwqc pg tg hshg. zzj kabhsq gdabwdecpk gk xwbaymx cb rgskte xwvyxekk dsje lshxdeowx xd niutqeyokm.
xwryw nrreksxmctrq mshgodj ecq igqscvgd ripfajjw eyguj yh vt lmi hnsw ushvzatr pf zztwt cxwamdhy dtztey gk jgrkvtq paj kjpu-qkljvbvtsymda czt lpq zg wiyril ylt nalmsgvzajw ds jaxxpaz, msmcsujris cuojvh. jk ezwi qkuqegr umw zxezmfp hrrnjw xzsmsi ib egzv hbbwwixttld, ikrt sx at pufymchk lt gdaywsx ib egzv ghrw tzte umw fdqowx. at jodq weeksi sjeywqztf guwshf zzj tantwy wd gnsy rd btw hec nxjjwi baj yldhmzyw.
lr caqp reksyi p ponnpxmglnsc bl lmi bvtv nr rlhwwweniw. ren vz tj qdek zzqpak ssh unoj ylpa zzj aderv dsje mgaigaswsxh ugnj qpqk tjjdek.
xqev vy ewgis balicrxw hvnczg hvppq efr, eyksxi pqj mshteyutvt ntv hygye twerry.
    """
key_dict = brute_force_decrypt(ciphertext, 6)
key = ""
for _ in key_dict:
    key += _[0][0]
print("私钥为"+key)
