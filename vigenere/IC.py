import re
import string


def filter_text(ciphertext):
    """预处理：去除非字母字符，转为大写"""
    return re.sub(r'[^a-zA-Z]', '', ciphertext).lower()


# 计算重合指数
def calc_ic(freq, text_length: int) -> float:
    ic = sum(count * (count - 1) for count in freq.values())
    ic /= text_length * (text_length - 1)
    return ic


def cal_freq(text: str):
    freq = {}
    for _ in string.ascii_lowercase:
        freq[_] = text.count(_)
    return freq


def guess_length(cipher, key_length):
    ic_std = 0.065
    cipher = filter_text(cipher.lower())

    # 按字符长度分组切片
    slices = ['' for _ in range(key_length)]
    for i, char in enumerate(cipher):
        slices[i % key_length] += char
    ic_value = []
    for s in slices:
        ic_value.append(calc_ic(cal_freq(s), len(s)))
    return sum(ic_value)/len(ic_value)


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
min_length = 3
max_length = 10
for i in range(min_length, max_length + 1):
    print("私钥长度为"+str(i)+"的IC值为"+str(guess_length(ciphertext, i)))
