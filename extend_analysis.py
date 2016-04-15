#!/usr/bin/env python
#coding:utf-8

__author__ = 'jiapeng'

from androlyze import *
import os
import os.path

class linkObj:
    def __init__(self,clz="",methd="",touchid="",flst=[]):
        self.clz = clz          #函数所属类
        self.methd = methd      #函数名
        self.touchid = touchid  #需要触发的控件的id
        self.flst = flst        #调用此函数的函数列表
    def setClz(self,strr):
        self.clz = strr
    def setMethd(self,strr):
        self.methd = strr
    def setTouchid(self,strr):
        self.touchid = strr
    def setFlst(sefl,ll):
        self.flst = ll
    def getClz(self):
        return self.clz
    def getMethd(self):
        return self.methd
    def getTouchid(self):
        return self.touchid
    def getFlst(self):
        return self.flst

class call_relation:
    def __init__(self, src_class_name, src_method_name, dst_class_name, dst_method_name):
        self.src_class_name = src_class_name
        self.src_method_name = src_method_name
        self.dst_class_name = dst_class_name
        self.dst_method_name = dst_method_name

def execmd(cmdstr):
    r = os.popen(cmdstr)
    result = r.read()
    r.close()
    return result

#将show_Permissions(dx)函数内部的逻辑规则改写，方便获取各种权限对应的调用函数
def get_permissions_path(dx):

    """
        Show where permissions are used in a specific application
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """

    p=dx.get_permissions([])
    perlist = []
    for i in p :
        if i == 'INTERNET':
            for j in p[i] :
                pers = show_Pathes( dx.get_vm(), j )
                perlist.append(pers)
    flist = []
    for i in range(0, len(perlist)):
        perline = perlist[i]
        # print perline
        src_relation = perline.split('--->')[0]
        dst_relation = perline.split('--->')[1]
        src_class_name = src_relation.split('->')[0]
        src_method_name = src_relation.split('->')[1]
        dst_class_name = dst_relation.split('->')[0]
        dst_method_name = dst_relation.split('->')[1]
        src_class_name = src_class_name[0: len(src_class_name)-1]
        dst_class_name = dst_class_name[0: len(dst_class_name)-1]
        # print src_relation, dst_relation
        # print src_class_name, src_method_name, dst_class_name, dst_method_name
        flist.append(call_relation(src_class_name, src_method_name, dst_class_name, dst_method_name))
    return flist

#改写./analysis.py中的show_path函数
def show_Pathes(vm, path) :
    cm = vm.get_class_manager()

    if isinstance(path, PathVar) :
        dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
        info_var = path.get_var_info()
        str1 = "%s %s (0x%x) ---> %s->%s%s" % (path.get_access_flag(),
                                              info_var,
                                              path.get_idx(),
                                              dst_class_name,
                                              dst_method_name,
                                              dst_descriptor)
    else :
        if path.get_access_flag() == TAINTED_PACKAGE_CALL :
            src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
            dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

            '''
            str2 = "%d %s->%s%s (0x%x) ---> %s->%s%s" % (path.get_access_flag(),
                                                         src_class_name,
                                                         src_method_name,
                                                         src_descriptor,
                                                         path.get_idx(),
                                                         dst_class_name,
                                                         dst_method_name,
                                                         dst_descriptor)
            '''
            str2 = "%s->%s%s ---> %s->%s%s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor)
            # print str2
            return str2
        else :
            src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
            '''
            str3 = "%d %s->%s%s (0x%x)" % (path.get_access_flag(),
                                           src_class_name,
                                           src_method_name,
                                           src_descriptor,
                                           path.get_idx() )
            '''
            str3 = "%s->%s%s" % (src_class_name, src_method_name, src_descriptor)
            # print str3
            return str3

#相当于show_xref()，获取起始函数的调用者
def getxref(d,clzstr,metstr1,metstr2):
   # print clzstr
#    print metstr1
 #   print metstr2
    print '--------------'
    str1f = []
    metstr = metstr1
  #  str1t = []
    clz = getattr(d,clzstr.strip(),'not find')#(d,'CLASS_Lcom_angles_fanbianyitry_MainActivity','not find')
    met = getattr(clz,metstr.strip(),'not find 2')#(clz,'METHOD_a_Landroid_content_ContextV','not find 2')
    if met!='not find 2':
        ##met.show_xref()
        try :
         #   bytecode._PrintSubBanner("XREF")
            str1f=bytecode._PrintXRef("F", met.XREFfrom.items)
         #   str1t=bytecode._PrintXRef("T", met.XREFto.items)
          #  bytecode._PrintSubBanner()
        except AttributeError:
            pass
    else:
        metstr = metstr2
        met = getattr(clz,metstr.strip(),'not find 3')
        ##met2.show_xref()
        try :
           # bytecode._PrintSubBanner("XREF")
            str1f=bytecode._PrintXRef("F", met.XREFfrom.items)
         #   str1t=bytecode._PrintXRef("T", met2.XREFto.items)
            #bytecode._PrintSubBanner()
        except AttributeError:
            pass
    return str1f,metstr

#相当于show_xref()，获取前一次获得的函数的调用者
def getfxerf(d,flist):
    for f in flist:
        fline = '_'.join(f.split('/'))           #对代表函数的字符串处理，提取出类和函数的参数、返回值等相关信息
    #    fline = '_'.join(fline.split('$'))
        fclzstr = fline.split()[1].split(';')[0]
        fmetstr = fline.split()[2]
        tempid = len(fline.split())-1
        while tempid >= 0:
          tempstr = fline.split()[tempid]
          if tempstr.endswith(';') or tempstr.endswith('V') or tempstr.endswith('I') or tempstr.endswith('Z') or tempstr.endswith('B') or tempstr.endswith('S') or tempstr.endswith('C') or tempstr.endswith('J') or tempstr.endswith('F') or tempstr.endswith('D'):
            break
          tempid -= 1
        fvarstr = str(fline.split()[3:tempid+1]).split("[")[1].split("]")[0]
        fvarstr = ''.join((''.join((''.join((''.join((''.join((''.join(fvarstr.split(", "))).split("'"))).split("("))).split(")"))).split(";"))).split('$'))
        fclzstr = 'CLASS_'+'_'.join(fclzstr.split('$'))
        fmetstr1 = 'METHOD_'+fmetstr
        fmetstr2 = 'METHOD_'+fmetstr +'_'+fvarstr
        print fclzstr
        print fmetstr1
        print fmetstr2
        fstrf2,fmetstrs2 = getxref(d,fclzstr,fmetstr1,fmetstr2)
        if len(fstrf2) != 0:#如果还有F：，即还有其他函数调用此函数，继续向上寻找调用者
            getfxerf(d,fstrf2)
        print '********************'#flist中的一个函数查询完毕

def main():
    #存储apk文件的目录
    rootdir = '/media/jiapeng/myfile/testapk'
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            file_dir = rootdir + '/' + filename
            apk, d, dx = AnalyzeAPK(file_dir)
            # get_permissions_path(dx)
            permissions_list = get_permissions_path(dx)
            permissions_list = list(set(permissions_list))
            for i in permissions_list:
                str_class = '_'.join(i.src_class_name.split('/'))
                str_method = '_'.join(i.src_method_name.split('/'))
                clzstr = 'CLASS_' + ''.join(str_class.split('$'))
                metstr = 'METHOD_' + ''.join(str_method.split('$'))


if __name__ == '__main__':
    main()