from django.contrib import admin

from .models import *

admin.site.register(UserDetails)
admin.site.register(FunFact)
admin.site.register(ReportedScams)
admin.site.register(ScamAnalysisResults)
admin.site.register(ScamAnalysis)
admin.site.register(RequestFeature)
