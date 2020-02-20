# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.contrib import messages
from django.shortcuts import render_to_response
from .search import *
from django.http import HttpResponse,JsonResponse,HttpResponseRedirect,Http404
from django.views.generic import View
from django.shortcuts import render, redirect
from . import models
from django.views.decorators.csrf import csrf_exempt
import datetime

# 全局报错页面处理
def page_not_found(request):
  return render_to_response('errorbase.html')

# 主页展示
class Index(View):

  def get(self, request):
    messages = models.Message.objects.all()
    return render(request, "index.html",{'messages' : messages})
    # return redirect('/knife/login/')

# 添加扫描任务
class Add(View):

  def get(self, request):
    return render(request, "addtask.html", )

  def post(self, request):
    if request.POST:
      publish = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
      target = request.POST.get("target")
      message = models.Message(target=target, publish=publish)
      message.save()
      return HttpResponseRedirect('/index/')


# 删除任务
class TaskDel(View):

    def get(self, request, **kwargs):
      task_id = kwargs['taskid']
      obj = models.Message.objects.get(id=task_id)
      if obj:
        obj.delete()
        return redirect('/index/')
      return Http404('资源不存在 {}'.format(task_id))

# 开始任务
class TaskShow(View):

  @csrf_exempt
  def post(self, request, **kwargs):
    taskid = (request.POST['taskid'])
    obj = models.Message.objects.get(id=taskid)
    if obj.result or obj.openresult:
      return HttpResponseRedirect('/index/')
    else:
      domain = obj.target
      subdomains_queue = multiprocessing.Manager().list()
      chosenEnums = [subDomainsBrute,DNSSearch,Bingsearch,Baidusaerch,Shodann,zoomeye,crtsearch,
                       Baiduapi,virustotal,ip138search,Google,threatcrowd,threatminer]
      enums = [enum(domain=domain, q=subdomains_queue) for enum in chosenEnums]
      for enum in enums:
        enum.run()
      total = (Y + "[-] 捕获子域名总数 : {}".format(len(set(list(subdomains_queue)))))
      content = (set(subdomains_queue))
      print(content)
      # publish = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
      models.Message.objects.filter(id=taskid).update(result=content)
      save = []
      import queue
      queue = queue.Queue()
      for i in range(3):
        t = is_alive(queue,domain=obj.target,save=save,taskid=taskid)
        t.setDaemon(True)
        t.start()
      for host in content:
        queue.put(host)
      queue.join()
      models.Message.objects.filter(id=taskid).update(showresult=content)
      return HttpResponseRedirect('/index/')


# 展示子域名收集结果
class Tasktext(View):

  def str_replace(self,text):
   text = text.replace('{','').replace('}','').replace("'",'').split(',')
   return text

  def get(self, request, **kwargs):
    taskid = int(kwargs['taskid'])
    obj = models.Message.objects.get(id=taskid)
    if obj.result:
      res = self.str_replace(obj.result)
      return render(request, "search.html",  {'messages': res})


# 刷新扫描结果
class Taskopen(View):

  def str_replace(self,text):
   text = text.replace('"','').replace(']','').replace('}','').replace('[','').split('{')
   return text

  def get(self, request, **kwargs):
    taskid = int(kwargs['taskid'])
    obj = models.Message.objects.get(id=taskid)
    if obj.openresult:
      res = self.str_replace(obj.openresult)
      return render(request, "search.html", {'messages': res})



