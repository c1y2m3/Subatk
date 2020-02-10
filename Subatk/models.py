# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class Message(models.Model):
  target = models.CharField(max_length=256)
  publish = models.DateTimeField()
  result = models.TextField(null=False,)
  openresult = models.TextField(null=False)
  showresult = models.TextField(null=False)



