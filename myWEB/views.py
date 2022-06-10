from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect

from django.contrib.auth.hashers import make_password, check_password  # 用户密码管理
from django.utils import timezone  # django带时区管理的时间类
from .models import dzTable, tsglyTable, smTable, tsTable, jsTable, yyTable, mail  # 引入数据库、
import mimetypes
from django.http import HttpResponseRedirect, HttpResponse
from cryptography.fernet import Fernet
import pymysql

key = Fernet.generate_key()
def home(request):
    return render(request, 'home.html')


def readfile(request):

    return render(request, 'robo.html')


def login_view(request):  # 读者、管理员用户登录
    context = dict()
    if request.method == 'POST':
        context["username"] = username = request.POST.get("username")
        password = request.POST.get("password")
        if username == '1234':
            if password == 'aVHtf0Myk5RDpbW':
                context['msg'] = "FLAG_2{:b'" + key.decode() + "'}"
            else:
                context['msg'] = 'Nice try'
            return render(request, 'home.html', context=context)
        if not username:
            context["msg"] = "Please input email, User ID or Staff ID"
            return render(request, 'home.html', context=context)
        if not password:
            context["msg"] = "Password missing"
            return render(request, 'home.html', context=context)
        if '@' in username:  # 读者使用邮箱登录
            #result = dzTable.objects.filter(email=username)
            if result.exists() and check_password(password, result[0].psw):  # 读者邮箱登录成功
                request.session['login_type'] = 'dz'
                request.session['id'] = result[0].dzid
                request.session['xm'] = result[0].xm
                return redirect('/dz_index/')
            else:
                context["msg"] = "Account or password error"
                return render(request, 'home.html', context=context)
        elif 'gh' in username:  # 管理员使用工号登录
            result = tsglyTable.objects.filter(gh=username)
            if result.exists() and password == result[0].psw:  # 管理员登录成功
                request.session['login_type'] = 'gly'
                request.session['id'] = result[0].gh
                request.session['xm'] = result[0].xm
                return redirect('/gly_index/')
            else:
                context["msg"] = "Wrong account or password"
                return render(request, 'home.html', context=context)
        else:  # 读者使用id登录
            conn = pymysql.connect(host='127.0.0.1', user='user', password='password', database='testdb', port=3306, charset='utf8')
            cur = conn.cursor()
            sql = "select * from testdb.myWEB_dztable where dzid='"+username+"';"
            count = cur.execute(sql)
            print('hi'%count)
            #获取第一行
            result = cur.fetchall()
            print(type(result[0][4]))
            #print(dateOne)
            #username = username.lstrip('0')
            #result = dzTable.objects.filter(dzid=username)
            print(type(password))
            if count > 0 and password == result[0][4]:
            #if result.exists() and check_password(password, result[0].psw):  # 读者id登录成功
                request.session['login_type'] = 'dz'
                request.session['id'] = result[0][0]
                request.session['xm'] = result[0][1]
                return redirect('/dz_index/')
            else:
                context["msg"] = "Wrong account or password"
                return render(request, 'home.html', context=context)
    else:
        return render(request, 'home.html')
def dz_puzzle(request):
    context=dict()
    if request.method == 'POST':
        context['psw'] = psw = request.POST.get("psw") # getting the password
        context['msg'] = msg = request.POST.get("msg") # getting the encrypted message
        #context['flag'] = flag = request.POST.get("flag") # The last flag
        tx_psw = psw[2:-1]
        tx_msg = msg[2:-1]
        en_psw = tx_psw.encode()
        en_msg = tx_msg.encode()
        print("the key is", en_psw, "The encrypted message is", en_msg, "type is", type(en_psw))
        fernet = Fernet(en_psw)
        flag = fernet.decrypt(en_msg)
        context['flag'] = flag  # getting the encrypted message
        print("You got your flag is", flag)
        return render(request, 'puzzle.html', context=context)
    else:
        return render(request,'puzzle.html', context = context )
    


def register(request):  # 新读者注册账户
    context = dict()
    if request.method == 'GET':
        return render(request, 'register.html', context=context)
    elif request.method == 'POST':
        context["xm"] = xm = request.POST.get("xm")  # 姓名
        context["dh"] = dh = request.POST.get("dh")  # 电话
        context["yx"] = yx = request.POST.get("yx")  # 邮箱
        mm = request.POST.get("mm")  # 密码
        mmqr = request.POST.get("mmqr")  # 密码确认
        context["msg"] = "Unknown Error"
        if not (xm and dh and yx and mm and mmqr):
            context['msg'] = "Double check your name, phone number, email and password"
            return render(request, 'register.html', context=context)
        if len(dh) != 10 or not dh.isdecimal():
            context["msg"] = "Invalid phone number"
            return render(request, 'register.html', context=context)
        if mm != mmqr:
            context["msg"] = "Use identical password!"
            return render(request, 'register.html', context=context)
        if len(mm) < 6:
            context["msg"] = "Minimum 6 characters for password"
            return render(request, 'register.html', context=context)
        if '@' not in yx:
            context["msg"] = "Invalid email"
            return render(request, 'register.html', context=context)
        result = dzTable.objects.filter(email=yx)
        if result.exists():
            context["msg"] = "The email has been registered. Please login. "
            return render(request, 'register.html', context=context)
        item = dzTable(
            xm=xm,
            dh=dh,
            email=yx,
            psw=make_password(mm)
        )
        item.save()
        result = dzTable.objects.get(email=yx)
        context["msg"] = "Successful! Your ID is: " + str(result.dzid).zfill(5)
        return render(request, 'register.html', context=context)
    else:
        return render(request, 'register.html', context=context)


def logout_view(request):  # 读者、管理员退出登录
    if request.session.get('login_type', None):
        request.session.flush()
    return HttpResponseRedirect("/")


"""
登录后的session:
request.session['login_type']: 读者'dz'  管理员'gly'
request.session['id']: 读者id  管理员工号 
request.session['xm']: 读者姓名 管理员姓名
"""

# =====================读者======================


def dz_index(request):  # 读者首页
    if request.session.get('login_type', None) != 'dz':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm')
    return render(request, 'dz_index.html', context=context)


def dz_smztcx(request):  # 读者书目状态查询
    if request.session.get('login_type', None) != 'dz':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm', None)
    if request.method == 'GET':
        return render(request, 'dz_smztcx.html', context=context)
    else:  # POST
        context['sm'] = sm = request.POST.get('sm')  # 书名
        context['zz'] = zz = request.POST.get('zz')  # 作者
        context['isbn'] = isbn = request.POST.get('isbn')  # ISBN
        context['cbs'] = cbs = request.POST.get('cbs')  # 出版社
        context['msg'] = "Unknown Error"
        result = smTable.objects.all()
        if not sm and not zz and not isbn and not cbs:
            context['msg'] = "Invalid input!"
            return render(request, 'dz_smztcx.html', context=context)
        if sm:
            result = result.filter(sm__contains=sm)
        if zz:
            result = result.filter(zz__contains=zz)
        if isbn:
            result = result.filter(isbn__startswith=isbn)
        if cbs:
            result = result.filter(cbs__contains=cbs)
        smzt = []
        for elem in result:
            smzt.append(
                {
                    'ISBN': elem.isbn,
                    'sm': elem.sm,
                    'zz': elem.zz,
                    'cbs': elem.cbs,
                    'cbny': elem.cbny,
                    'kccs': len(tsTable.objects.filter(isbn=elem.isbn)),
                    'bwjcs': len(tsTable.objects.filter(isbn=elem.isbn, zt='N')),
                    'wjccs': len(tsTable.objects.filter(isbn=elem.isbn, zt='Available')),
                    'yjccs': len(tsTable.objects.filter(isbn=elem.isbn, zt='Borrowed')),
                    'yyycs': len(tsTable.objects.filter(isbn=elem.isbn, zt='Reserved')),
                }
            )
        context['msg'] = ''
        context['smzt'] = smzt
        return render(request, 'dz_smztcx.html', context=context)


def dz_yydj(request):  # 读者预约登记(借不到的书)
    if request.session.get('login_type', None) != 'dz':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm', None)
    yydj = []
    result = yyTable.objects.filter(dzid_id=request.session.get('id', None))
    for elem in result:
        yydj.append(
            {
                'ISBN': elem.isbn.isbn,
                'sm': smTable.objects.get(isbn=elem.isbn.isbn).sm,
                'yysj': elem.yysj,
                'tsid': elem.tsid.tsid if elem.tsid else None,
            }
        )
    context['yydj'] = yydj
    if request.method == 'GET':
        return render(request, 'dz_yydj.html', context=context)
    elif request.method == 'POST':
        context['msg'] = "Unknown Error"
        context['ISBN'] = isbn = request.POST.get('ISBN')
        if not isbn:
            context['msg'] = "Reserve by ISBN"
            return render(request, 'dz_yydj.html', context=context)
        result = smTable.objects.filter(isbn=isbn)
        if not result.exists():
            context['msg'] = "Invalid ISBN"
            return render(request, 'dz_yydj.html', context=context)
        result = tsTable.objects.filter(isbn=isbn, zt='Available')
        if result.exists():
            context['msg'] = "The book is in stock and available for borrowing (Book ID：" + str(result[0].tsid) + ")"
            return render(request, 'dz_yydj.html', context=context)
        result = yyTable.objects.filter(isbn=isbn, dzid=request.session.get('id', None))
        if result.exists():
            context['msg'] = "Do not reserve it twice"
            return render(request, 'dz_yydj.html', context=context)
        item = yyTable(
            dzid_id=request.session.get('id', None),
            isbn=smTable.objects.get(isbn=isbn),
            yysj=timezone.now(),
            # tsid_id=None
        )
        item.save()
        context['msg'] = "Reservation successful! The confirmation has been sent to your email. "
        yydj = []
        result = yyTable.objects.filter(dzid_id=request.session.get('id', None))
        for elem in result:
            yydj.append(
                {
                    'ISBN': elem.isbn.isbn,
                    'sm': smTable.objects.get(isbn=elem.isbn.isbn).sm,
                    'yysj': elem.yysj,
                    'tsid': elem.tsid.tsid if elem.tsid else None
                }
            )
        context['yydj'] = yydj
        return render(request, 'dz_yydj.html', context=context)
def download_file(request):
    # file name
    fl_path = 'a.txt'

    fernet = Fernet(key)
    with open('a.txt', 'rb') as file:
        original = file.read()

    encrypted = fernet.encrypt(original)
    
    with open('a.txt', 'wb') as encrypted_file:
        encrypted_file.write("b'".encode() + encrypted+ "'".encode())
        encrypted_file.close()

    # download name
    filename = 'flag.txt'
    fl = open(fl_path, 'rb')
    print(fl)
    #encMessage = fernet.encrypt(fl)
    mime_type, _ = mimetypes.guess_type(fl_path)
    response = HttpResponse(fl, content_type=mime_type)
    response['Content-Disposition'] = "attachment; filename=%s" % filename

    return response



def dz_grztcx(request):  # 读者个人(借书)状态查询
    if request.session.get('login_type', None) != 'dz':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm', None)
    result = jsTable.objects.filter(dzid_id=request.session.get('id'))
    grzt = []
    for elem in result:
        grzt.append(
            {
                'tsid': elem.tsid.tsid,
                'sm': elem.tsid.isbn.sm,
                'jysj': elem.jysj,
                'yhsj': elem.yhsj,
                'ghsj': elem.ghsj
            }
        )
    context['grzt'] = grzt
    return render(request, 'dz_grztcx.html', context=context)


# =====================管理员======================


def gly_index(request):  # 管理员首页
    if request.session.get('login_type', None) != 'gly':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm')
    if request.method == 'GET':
        return render(request, 'gly_index.html', context=context)
    else:
        result = yyTable.objects.extra(where=["""datediff(curdate(), yysj) > 10"""])
        for elem in result:
            mail(
                "预约过期通知",
                "很遗憾，您预约的书《" + elem.isbn.sm + "》预约时间已经过期，您可以再次尝试预约",
                elem.dzid.email
            )
            if elem.tsid:  # 已经被成功预约，清除预约状态
                ts = elem.tsid
                yyy = yyTable.objects.filter(isbn=elem.isbn, tsid=None)
                if yyy.exists():  # 还有别人等待预约，更新图书归属预约信息，不用更新图书状态
                    yyy = yyy[0]
                    yyy.tsid = elem.tsid
                    yyy.save()
                else:  # 没有人等待预约，更新图书状态
                    ts.zt = '未借出'
                    ts.save()
        context['msg1'] = "清理" + str(len(result)) + "份过期预约信息。"
        result.delete()
        result = jsTable.objects.filter(ghsj=None).extra(where=["""datediff(curdate(), yhsj) = 0"""])
        for elem in result:
            mail(
                "借书归还通知",
                "您借阅的书《" + str(elem.tsid.isbn.sm) + "》即将逾期归还，请注意及时还书",
                elem.dzid.email
            )
        context['msg2'] = "提示" + str(len(result)) + "份逾期归还信息。"
        return render(request, 'gly_index.html', context=context)


def gly_smztcx(request):  # 管理员书目状态查询
    if request.session.get('login_type', None) != 'gly':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm', None)
    if request.method == 'GET':
        return render(request, 'gly_smztcx.html', context=context)
    else:
        context['sm'] = sm = request.POST.get('sm')  # 书名
        context['zz'] = zz = request.POST.get('zz')  # 作者
        context['isbn'] = isbn = request.POST.get('isbn')  # ISBN
        context['cbs'] = cbs = request.POST.get('cbs')  # 出版社
        context['msg'] = "未知错误，请重试"
        result = smTable.objects.all()
        if sm:
            result = result.filter(sm__contains=sm)
        if zz:
            result = result.filter(zz__contains=zz)
        if isbn:
            result = result.filter(isbn__startswith=isbn)
        if cbs:
            result = result.filter(cbs__contains=cbs)
        smzt = []
        for elem in result:
            smzt.append(
                {
                    'ISBN': elem.isbn,
                    'sm': elem.sm,
                    'zz': elem.zz,
                    'cbs': elem.cbs,
                    'cbny': elem.cbny,
                    'kccs': len(tsTable.objects.filter(isbn=elem.isbn)),
                    'bwjcs': len(tsTable.objects.filter(isbn=elem.isbn, zt='不外借')),
                    'wjccs': len(tsTable.objects.filter(isbn=elem.isbn, zt='未借出')),
                    'yjccs': len(tsTable.objects.filter(isbn=elem.isbn, zt='已借出')),
                    'yyycs': len(tsTable.objects.filter(isbn=elem.isbn, zt='已预约')),
                }
            )
        context['msg'] = ''
        context['smzt'] = smzt
        return render(request, 'gly_smztcx.html', context=context)


def gly_js(request):  # 管理员借书
    if request.session.get('login_type', None) != 'gly':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm')
    if request.method == 'GET':
        return render(request, 'gly_js.html', context=context)
    else:
        context['dzid'] = dzid = request.POST.get('dzid')
        context['isbn'] = isbn = request.POST.get('isbn')
        context['msg'] = "未知错误，请重试"
        if not dzid or not isbn:
            context['msg'] = "请填写完整的读者id和ISBN号"
            return render(request, 'gly_js.html', context=context)
        if not dzid.isdecimal():
            context['msg'] = "读者id不存在！"
            return render(request, 'gly_js.html', context=context)
        result = dzTable.objects.filter(dzid=dzid)
        if not result.exists():
            context['msg'] = "读者id不存在！"
            return render(request, 'gly_js.html', context=context)
        result = smTable.objects.filter(isbn=isbn)
        if not result.exists():
            context['msg'] = "ISBN号填写错误，不存在该类书籍！"
            return render(request, 'gly_js.html', context=context)
        result = jsTable.objects.filter(dzid_id=dzid, ghsj=None)
        if len(result) >= 10:
            context['msg'] = "该读者借阅书籍数已经达到上限！"
            return render(request, 'gly_js.html', context=context)
        result = yyTable.objects.filter(dzid_id=dzid, isbn_id=isbn)
        if result.exists() and result[0].tsid_id is not None:  # 借书有过预约，且预约成功（删除预约、添加借书信息、修改图书状态）
            ts = result[0].tsid
            ts.zt = '已借出'
            ts.save()  # 修改图书状态
            item = jsTable(
                dzid_id=dzid,
                tsid=result[0].tsid,
                jysj=timezone.now(),
                yhsj=timezone.now() + timezone.timedelta(days=60)
            )
            item.save()  # 添加借书信息
            result[0].delete()  # 删除预约
            context['msg'] = "借阅成功（已预约）！（图书id：" + str(item.tsid.tsid) + "）"
            return render(request, 'gly_js.html', context=context)
        else:  # 未预约直接借书（添加借书信息、修改图书状态）
            result = tsTable.objects.filter(isbn_id=isbn, zt='未借出')
            if not result.exists():
                context['msg'] = "该图书已全部被借出或预约，无法借阅！"
                return render(request, 'gly_js.html', context=context)
            result = result[0]
            result.zt = '已借出'
            result.save()  # 修改图书状态
            item = jsTable(
                dzid_id=dzid,
                tsid=result,
                jysj=timezone.now(),
                yhsj=timezone.now() + timezone.timedelta(days=60)
            )
            item.save()  # 添加借书信息
            context['msg'] = "借阅成功（未预约）！（图书id：" + str(result.tsid) + "）"
            return render(request, 'gly_js.html', context=context)


def gly_hs(request):  # 管理员还书
    if request.session.get('login_type', None) != 'gly':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm')
    if request.method == 'GET':
        return render(request, 'gly_hs.html', context=context)
    else:
        context['dzid'] = dzid = request.POST.get('dzid')
        context['tsid'] = tsid = request.POST.get('tsid')
        context['msg'] = "未知错误，请重试"
        if not dzid or not tsid:
            context['msg'] = "请填写完整的读者id和ISBN号"
            return render(request, 'gly_hs.html', context=context)
        if not dzid.isdecimal() or not tsid.isdecimal():
            context['msg'] = "读者id和图书id必须是数字！"
            return render(request, 'gly_hs.html', context=context)
        result = dzTable.objects.filter(dzid=dzid)
        if not result.exists():
            context['msg'] = "读者id不存在！"
            return render(request, 'gly_hs.html', context=context)
        result = tsTable.objects.filter(tsid=tsid)
        if not result.exists():
            context['msg'] = "不存在该图书id！"
            return render(request, 'gly_hs.html', context=context)
        result = jsTable.objects.filter(dzid_id=dzid, tsid_id=tsid, ghsj=None)  # 未归还的借书记录
        if not result.exists():
            context['msg'] = "该读者未借阅该图书！"
            return render(request, 'gly_hs.html', context=context)
        result = result[0]
        if timezone.now() - result.yhsj > timezone.timedelta(days=0):  # 逾期未还
            context['msg'] = "图书逾期归还，应该缴纳费用" + str((timezone.now() - result.yhsj).days * 0.1) + "元"
        else:  # 期限内归还
            context['msg'] = "图书期限内归还"
        isbn = tsTable.objects.get(tsid=tsid).isbn_id
        yy = yyTable.objects.filter(isbn_id=isbn, tsid=None)
        ts = tsTable.objects.get(tsid=tsid)
        if yy.exists():  # 有人预约此书却没有预约到
            yy = yy[0]
            yy.tsid_id = tsid
            yy.save()  # 更新预约表
            ts.zt = '已预约'
            ts.save()  # 更新图书为已预约
        else:  # 无人未预约到此书
            ts.zt = '未借出'
            ts.save()
        result.ghsj = timezone.now()  # 归还此书
        result.save()
        return render(request, 'gly_hs.html', context=context)


def gly_rk(request):  # 管理员入库
    if request.session.get('login_type', None) != 'gly':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm')
    if request.method == 'GET':
        return render(request, 'gly_rk.html', context=context)
    else:
        context['isbn'] = isbn = request.POST.get('isbn')  # ISBN
        context['rksl'] = rksl = request.POST.get('rksl')  # 入库数量
        context['rkhzt'] = rkhzt = request.POST.get('rkhzt')  # 入库后状态（流通室、阅览室）
        context['sm'] = sm = request.POST.get('sm')  # 书名（新书录入）
        context['zz'] = zz = request.POST.get('zz')  # 作者（新书录入）
        context['cbs'] = cbs = request.POST.get('cbs')  # 出版社（新书录入）
        context['cbny'] = cbny = request.POST.get('cbny')  # 出版年月（新书录入）
        # context['cs'] = cs = request.POST.get('cs')  # 册数（新书录入）
        context['msg'] = "未知错误，请重试"
        if not isbn or not rksl or not rkhzt:
            context['msg'] = "请填写ISBN号、入库数量和入库后状态"
            return render(request, 'gly_rk.html', context=context)
        if rkhzt != '流通室' and rkhzt != '阅览室':
            context['msg'] = "入库后状态必须为流通室或阅览室"
            return render(request, 'gly_rk.html', context=context)
        result = smTable.objects.filter(isbn=isbn)
        if result.exists():  # 旧书录入
            if sm:
                result = result.filter(sm__contains=sm)
                if not result.exists():
                    context['msg'] = "检测到旧书录入，且书名信息不匹配，请检查"
                    return render(request, 'gly_rk.html', context=context)
            if zz:
                result = result.filter(zz__contains=zz)
                if not result.exists():
                    context['msg'] = "检测到旧书录入，且作者信息不匹配，请检查"
                    return render(request, 'gly_rk.html', context=context)
            if cbs:
                result = result.filter(cbs__contains=cbs)
                if not result.exists():
                    context['msg'] = "检测到旧书录入，且出版社信息不匹配，请检查"
                    return render(request, 'gly_rk.html', context=context)
            if cbny:
                result = result.filter(cbny=cbny)
                if not result.exists():
                    context['msg'] = "检测到旧书录入，且出版年月不匹配，请检查"
                    return render(request, 'gly_rk.html', context=context)
            if rkhzt == '流通室':  # 注意先检查是否有预约
                for _ in range(int(rksl)):
                    yy = yyTable.objects.filter(isbn_id=isbn, tsid=None)
                    if yy.exists():  # 归入预约
                        item = tsTable(
                            isbn_id=isbn,
                            cfwz='图书流通室',
                            zt='已预约',
                            jbr_id=request.session.get('id')
                        )
                        item.save()
                        yy = yy[0]
                        yy.tsid_id = item.tsid
                        yy.save()  # 更新预约表
                    else:
                        item = tsTable(
                            isbn_id=isbn,
                            cfwz='图书流通室',
                            zt='未借出',
                            jbr_id=request.session.get('id')
                        )
                        item.save()
            else:  # 阅览室不外借
                for _ in range(int(rksl)):
                    item = tsTable(
                        isbn_id=result[0].isbn,
                        cfwz='图书阅览室',
                        zt='不外借',
                        jbr_id=request.session.get('id')
                    )
                    item.save()
            context['msg'] = "旧书入库成功！"
        else:   # 新书录入
            if not (sm and zz and cbs and cbny):
                context['msg'] = "检测到新书录入，请完整填写信息"
                return render(request, 'gly_rk.html', context=context)
            item = smTable(
                isbn=isbn,
                sm=sm,
                zz=zz,
                cbs=cbs,
                cbny=cbny,
                jbr_id=request.session.get('id'),
            )
            item.save()
            if rkhzt == '流通室':  # 注意先检查是否有预约
                for _ in range(int(rksl)):
                    yy = yyTable.objects.filter(isbn_id=isbn, tsid=None)
                    if yy.exists():  # 归入预约
                        item = tsTable(
                            isbn_id=isbn,
                            cfwz='图书流通室',
                            zt='已预约',
                            jbr_id=request.session.get('id')
                        )
                        item.save()
                        yy = yy[0]
                        yy.tsid_id = item.tsid
                        yy.save()  # 更新预约表
                    else:
                        item = tsTable(
                            isbn_id=isbn,
                            cfwz='图书流通室',
                            zt='未借出',
                            jbr_id=request.session.get('id')
                        )
                        item.save()
            else:  # 阅览室不外借
                for _ in range(int(rksl)):
                    item = tsTable(
                        isbn_id=isbn,
                        cfwz='图书阅览室',
                        zt='不外借',
                        jbr_id=request.session.get('id')
                    )
                    item.save()
            context['msg'] = "新书入库成功！"
        return render(request, 'gly_rk.html', context=context)


def gly_ck(request):  # 管理员出库
    if request.session.get('login_type', None) != 'gly':
        return HttpResponseRedirect("/")
    context = dict()
    context['xm'] = request.session.get('xm')
    if request.method == 'GET':
        return render(request, 'gly_ck.html', context=context)
    else:
        context['isbn'] = isbn = request.POST.get('isbn')  # ISBN
        context['cksl'] = cksl = request.POST.get('cksl')  # 出库数量
        context['ckyx'] = ckyx = request.POST.get('ckyx')  # 出库优先（未借出、不外借）
        context['msg'] = "未知错误，请重试"
        if not isbn or not cksl or not ckyx:
            context['msg'] = "请填写ISBN号、入出库数量和优先出库位置"
            return render(request, 'gly_ck.html', context=context)
        if ckyx != '流通室' and ckyx != '阅览室':
            context['msg'] = "优先出库位置必须为流通室或阅览室"
            return render(request, 'gly_ck.html', context=context)
        result = smTable.objects.filter(isbn=isbn)
        if not result.exists():
            context['msg'] = "ISBN录入有误，请检查"
            return render(request, 'gly_ck.html', context=context)
        wjc = tsTable.objects.filter(isbn_id=isbn, zt='未借出')  # 未借出图书数量
        bwj = tsTable.objects.filter(isbn_id=isbn, zt='不外借')  # 不外借图书数量
        yyy = tsTable.objects.filter(isbn_id=isbn, zt='已预约')  # 已预约图书数量
        ts = tsTable.objects.filter(isbn_id=isbn)  # 所有图书数量
        cksl = int(cksl)
        if len(ts) < cksl:
            context['msg'] = "出库数量超过藏书总数！请检查"
            return render(request, 'gly_ck.html', context=context)
        if len(wjc) + len(bwj) + len(yyy) < cksl:
            context['msg'] = "由于部分书目已被借出，出库失败！"
            return render(request, 'gly_ck.html', context=context)
        tsid = ''
        ck = []
        if ckyx == '流通室':  # 未借出 > 已预约 > 不外借
            for elem in wjc:
                if cksl > 0:
                    tsid += str(elem.tsid) + ' '
                    ck.append(elem)
                    cksl -= 1
                else:
                    break
            for elem in yyy:
                if cksl > 0:
                    tsid += str(elem.tsid) + ' '
                    mail(
                        "预约失效通知",
                        "由于管理员出库，您预约的图书《" + smTable.objects.get(isbn=isbn).sm + "》不再存储，预约已经失效。",
                        yyTable.objects.get(tsid=elem.tsid).dzid.email,
                    )
                    ck.append(elem)
                    cksl -= 1
                else:
                    break
            for elem in bwj:
                if cksl > 0:
                    tsid += str(elem.tsid) + ' '
                    ck.append(elem)
                    cksl -= 1
                else:
                    break
            for elem in ck:
                elem.delete()
            context['msg'] = "出库成功！"
            context['tsid'] = tsid
        else:  # 不外借 > 未借出 > 已预约
            for elem in bwj:
                if cksl > 0:
                    tsid += str(elem.tsid) + ' '
                    ck.append(elem)
                    cksl -= 1
                else:
                    break
            for elem in wjc:
                if cksl > 0:
                    tsid += str(elem.tsid) + ' '
                    ck.append(elem)
                    cksl -= 1
                else:
                    break
            for elem in yyy:
                if cksl > 0:
                    tsid += str(elem.tsid) + ' '
                    mail(
                        "预约失效通知",
                        "由于管理员出库，您预约的图书《" + smTable.objects.get(isbn=isbn).sm + "》不再存储，预约已经失效。",
                        yyTable.objects.get(tsid=elem.tsid).dzid.email,
                    )
                    ck.append(elem)
                    cksl -= 1
                else:
                    break
            for elem in ck:
                elem.delete()
            context['msg'] = "出库成功！"
            context['tsid'] = tsid
        return render(request, 'gly_ck.html', context=context)
