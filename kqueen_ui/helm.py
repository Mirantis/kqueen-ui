from kqueen_ui import cache

import asyncio
import concurrent.futures
import requests
import yaml


class HelmChart:
    name = None
    description = None
    icon = None
    version = None
    tag = '-'

    def __init__(self, name=None, description=None, icon=None, version=None, **kwargs):
        self.name = name
        self.description = description
        self.icon = icon
        if not self.icon:
            self.icon = 'http://www.metalmusicarchives.com/images/artists/mindwar(malaysia)-20170608082858.jpg'
        self.version = version
        self.tag = self.name[0].capitalize()

    def __str__(self):
        return '{} - {}'.format(self.name, self.version)

    def __repr__(self):
        return '<HelmChart: {} - {}>'.format(self.name, self.version)


class HelmHandler:
    repo_url = 'https://api.github.com/repos/kubernetes/charts/contents/stable'
    chart_meta_url = 'https://raw.githubusercontent.com/kubernetes/charts/master/stable/{}/Chart.yaml'

    def _get(self, url, headers={}):
        return requests.get(url, headers=headers, timeout=3)

    def _get_chart(self, name):
        cache_key = 'helm-{}'.format(name)
        cached_chart = cache.get(cache_key)
        if cached_chart:
            return HelmChart(**cached_chart)
        response = self._get(self.chart_meta_url.format(name))
        chart_meta = yaml.load(response.text)
        cache.set(cache_key, chart_meta, 60 * 60)
        return HelmChart(**chart_meta)

    async def _get_chart_list(self, loop, chart_names):
        responses = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                loop.run_in_executor(
                    executor, 
                    self._get_chart,
                    cname
                )
                for cname in chart_names
            ]
        for response in await asyncio.gather(*futures):
            responses.append(response)
        return responses

    def get_catalog(self):
        res = self._get(self.repo_url)
        chart_dirs = res.json()
        chart_names = [chdir['name'] for chdir in chart_dirs]
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.SelectorEventLoop()
        charts = loop.run_until_complete(self._get_chart_list(loop, chart_names))
        return charts
