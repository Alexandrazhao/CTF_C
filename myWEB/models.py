from django.db import models

import smtplib  # 邮件服务
from email.mime.text import MIMEText  # 邮件服务
from email.utils import formataddr  # 邮件服务

from time import sleep  # 发邮件需要睡觉
from django.utils import timezone


def mail(title, content, my_user, coding_type='HTML', retry_flag=False):  # 寄送邮件服务
    my_sender = '905157677@qq.com'  # 发件人邮箱账号
    my_pass = 'rbtplvuhmqgmbaid'  # 发件人邮箱口令
    really_mail = True
    print("\n=================发送邮件====================")
    print("|| Receiver：" + my_user)
    print("|| Title：" + title)
    print("|| Content：" + content)
    print("============================================\n")
    if not really_mail:
        return
    while True:
        try:
            msg = MIMEText(content, coding_type, 'utf-8')
            msg['From'] = formataddr(['Conan', my_sender])
            msg['To'] = formataddr(['User', my_user])
            msg['Subject'] = title
            server = smtplib.SMTP_SSL('smtp.qq.com', 465)
            server.login(my_sender, my_pass)
            server.sendmail(my_sender, [my_user, ], msg.as_string())
            server.quit()
        except Exception as err:
            print('in mailing ', err)
            if not retry_flag:
                break
            sleep(5)
            continue
        return


class dzTable(models.Model):  # 读者信息
    dzid = models.AutoField(primary_key=True)  # 读者ID
    psw = models.CharField(max_length=256)  # 读者密码
    xm = models.CharField(max_length=10)  # 姓名
    dh = models.CharField(max_length=20)  # 电话
    email = models.CharField(max_length=50)  # 邮箱

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        result = dzTable.objects.filter(email=self.email)
        assert not result.exists(), 'Try different email'
        super(dzTable, self).save(force_insert, force_update, using, update_fields)
        mail(
            "Registration",
            "Registration completed! Your name is：" + str(self.xm) + "and ID is：" + str(self.dzid).zfill(5),
            self.email,
        )


class tsglyTable(models.Model):  # 图书管理员信息
    gh = models.CharField(max_length=10, primary_key=True)  # 工号，格式：gh001
    psw = models.CharField(max_length=256)  # 管理员密码
    xm = models.CharField(max_length=10)  # 姓名

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        assert str(self.gh).startswith('gh')
        super(tsglyTable, self).save(force_insert, force_update, using, update_fields)


class smTable(models.Model):  # 书目信息
    isbn = models.CharField(max_length=50, primary_key=True)  # ISBN号
    sm = models.CharField(max_length=50)  # 书名
    zz = models.CharField(max_length=50)  # 作者
    cbs = models.CharField(max_length=50)  # 出版商
    cbny = models.DateTimeField()  # 出版年月
    # cs = models.IntegerField()   # 册数
    jbr = models.ForeignKey(tsglyTable, on_delete=models.CASCADE)  # 经办人


class tsTable(models.Model):  # 图书信息
    tsid = models.AutoField(primary_key=True)  # 图书id
    isbn = models.ForeignKey(smTable, on_delete=models.CASCADE)  # ISBN号
    cfwz = models.CharField(max_length=20)  # 存放位置(图书流通室、图书阅览室)
    zt = models.CharField(max_length=20)  # 状态（未借出、已借出、不外借、已预约）
    jbr = models.ForeignKey(tsglyTable, on_delete=models.CASCADE)  # 经办人

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        assert self.cfwz in ('Reception', 'Reading room'), 'Either Reception or Reading room'
        assert self.zt in ('Available', 'Borrowed', 'N', 'Reserved'), 'Status book includes ' \
                                                                      'Available、Borrowed、N、Reserved '
        super(tsTable, self).save(force_insert, force_update, using, update_fields)

    def delete(self, using=None, keep_parents=False):  # 出库触发器
        assert self.zt != 'Borrowed', 'Not available'
        super(tsTable, self).delete(using, keep_parents)
        if self.zt == 'Reserved':
            mail(
                "Notification",
                "The book " + smTable.objects.get(isbn=self.isbn).sm + " is now out of stock. Reservation expired. ",
                yyTable.objects.get(tsid=self.tsid).dzid.email,
            )


class jsTable(models.Model):  # 借书信息
    dzid = models.ForeignKey(dzTable, on_delete=models.PROTECT)  # 读者ID
    tsid = models.ForeignKey(tsTable, on_delete=models.PROTECT)  # 图书ID
    jysj = models.DateTimeField()  # 借阅时间
    yhsj = models.DateTimeField()  # 应还时间
    ghsj = models.DateTimeField(blank=True, null=True)  # 归还时间

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        assert self.jysj < self.yhsj, 'Return the book after borrowing'
        super(jsTable, self).save(force_insert, force_update, using, update_fields)
        if not self.ghsj:  # 借书
            mail(
                "Confirmation",
                "The book " + self.tsid.isbn.sm + " is borrowed successfully!",
                self.dzid.email
            )
        else:  # 还书
            mail(
                "Confirmation",
                "The book " + self.tsid.isbn.sm + " is returned successfully!",
                self.dzid.email
            )

    class Meta:
        unique_together = ("dzid", "tsid", "jysj")


class yyTable(models.Model):  # 预约信息
    dzid = models.ForeignKey(dzTable, on_delete=models.CASCADE)  # 读者ID
    isbn = models.ForeignKey(smTable, on_delete=models.CASCADE)  # ISBN号
    tsid = models.ForeignKey(tsTable, blank=True, null=True, on_delete=models.CASCADE)  # 图书ID
    yysj = models.DateTimeField()

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):  # 创建预约触发器
        super(yyTable, self).save(force_insert, force_update, using, update_fields)
        if not self.tsid:  # 新建预约没有图书id
            mail(
                "Notification",
                "You have reserved the book " + str(self.isbn.sm) +
                " at " + str(timezone.now()),
                self.dzid.email
            )
        else:  # 预约更新添加图书id
            mail(
                "Notification",
                "The book " + str(self.isbn.sm) + " is now on stock. Please borrow it while it is available",
                self.dzid.email
            )

    class Meta:
        unique_together = ("dzid", "isbn", "yysj")
