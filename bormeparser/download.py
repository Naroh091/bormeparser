#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# download.py -
# Copyright (C) 2015-2022 Pablo Castellano <pablo@anche.no>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import datetime
import os
import requests
import time
from lxml import etree
from threading import Thread

from .exceptions import BormeDoesntExistException
from .parser import parse as parse_borme
from .seccion import SECCION

requests.adapters.DEFAULT_RETRIES = 3

from queue import Queue

import logging
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
logger.addHandler(ch)
logger.setLevel(logging.WARN)

# URLs

# DON'T REWRITE BY DEFAULT
# TODO: comprobar bytes

# TODO: boe.gob.es es un mirror? Resuelve a una IP distinta.
BORME_AB_PDF_URL = "{protocol}://boe.es/borme/dias/{year}/{month:02d}/{day:02d}/pdfs/BORME-{seccion}-{year}-{nbo}-{provincia}.pdf"
BORME_XML_URL = "https://www.boe.es/datosabiertos/api/borme/sumario/{year}{month:02d}{day:02d}"
BORME_C_HTM_URL = "{protocol}://boe.es/diario_borme/txt.php?id=BORME-C-{year}-{anuncio}"
BORME_C_PDF_URL = "{protocol}://boe.es/borme/dias/{year}/{month:02d}/{day:02d}/pdfs/BORME-C-{year}-{anuncio}.pdf"
BORME_C_XML_URL = "{protocol}://boe.es/diario_borme/xml.php?id=BORME-C-{year}-{anuncio}"

URL_BASE = '%s://www.boe.es'
USE_HTTPS = True

# Download threads
THREADS = 8


# date = (year, month, date) or datetime.date
# filename = path to filename or just filename
def download_xml(date, filename, secure=USE_HTTPS, forcedownload=False):
    url = get_url_xml(date, secure=secure)
    downloaded = download_url(url, filename, forcedownload=forcedownload, headers={'Accept': 'application/xml'})
    return downloaded


def download_pdfs(date, path, provincia=None, seccion=None, secure=USE_HTTPS, forcedownload=False):
    """ Descarga BORMEs PDF de las provincia, la seccion y la fecha indicada """
    urls = get_url_pdfs(date, provincia=provincia, seccion=seccion, secure=secure)
    files = download_urls(urls, path, forcedownload=forcedownload)
    return True, files


# date = (year, month, date) or datetime.date
# seccion = ('A', 'B', 'C') or SECCION.A, SECCION.B, ...
# province = class PROVINCIA: PROVINCIA.MALAGA, PROVINCIA.MADRID, ...
def download_pdf(date, filename, seccion, provincia, parse=False, forcedownload=False):
    """ Descarga BORME PDF de la provincia, la seccion y la fecha indicada """
    url = get_url_pdf(date, seccion, provincia)
    downloaded = download_url(url, filename, forcedownload=forcedownload)

    if downloaded:
        logger.debug('Downloaded: {}'.format(filename))
    else:
        logger.debug('File already exists: {}'.format(filename))

    if not parse:
        return False

    if parse:
        return parse_borme(filename, seccion)

    return True


# No se puede porque van numerados. Ademas de la fecha, el tipo y la provincia necesitariamos saber el numero de
# borme del año. Lo unico que se podria hacer es bajar el xml y ahi ver la url
# date = (year, month, date) or datetime.date
# seccion = ('A', 'B', 'C') or class SECCION
# province = class PROVINCIA
# "http://boe.es/borme/dias/2015/06/01/pdfs/BORME-A-2015-101-29.pdf"
def get_url_pdf(date, seccion, provincia, secure=USE_HTTPS):
    """ Devuelve la URL para descargar un BORME
        Nota: Requiere conexión a Internet
    """
    if isinstance(date, tuple):
        date = datetime.date(year=date[0], month=date[1], day=date[2])

    url = get_url_xml(date, secure=secure)
    nbo = get_nbo_from_xml(url)
    protocol = 'https' if secure else 'http'

    return BORME_AB_PDF_URL.format(protocol=protocol, year=date.year, month=date.month, day=date.day,
                                   seccion=seccion, nbo=nbo, provincia=provincia.code)


def get_url_pdf_from_xml(date, seccion, provincia, xml_path, secure=USE_HTTPS):
    """ Devuelve la URL para descargar un BORME """
    if isinstance(date, tuple):
        date = datetime.date(year=date[0], month=date[1], day=date[2])

    nbo = get_nbo_from_xml(xml_path)
    protocol = 'https' if secure else 'http'

    return BORME_AB_PDF_URL.format(protocol=protocol, year=date.year, month=date.month, day=date.day,
                                   seccion=seccion, nbo=nbo, provincia=provincia.code)

"""
# Needs research
def get_url_borme_c(date, some_number, format='xml'):
    if format == 'xml':
        return BORME_C_XML_URL.format(protocol=protoco, year=date.year, anuncio=some_number)
    elif format in ('htm', 'html'):
        return BORME_C_HTM_URL.format(protocol=protocol, year=date.year, anuncio=some_number)
    elif format == 'pdf':
        return BORME_C_PDF_URL.format(protocol=protocol, year=date.year, month=date.month, day=month.day, anuncio=some_number)
    else:
        raise ValueError('format must be "xml", "htm" or "pdf"')
"""

def get_nbo_from_xml(source):
    """ Devuelve el Número de Boletín Oficial (nbo)
        source: url o path
        Nota: Requiere conexión a Internet si source es una URL
    """
    if source.startswith('http'):
        req = requests.get(source, headers={'Accept': 'application/xml'})
        content = req.content
        tree = etree.fromstring(content).getroottree()
    else:
        tree = etree.parse(source)

    root = tree.getroot()
    if root.tag == 'response':
        status = root.find('status/code')
        if status is not None and status.text != '200':
            raise BormeDoesntExistException
        diario = root.find('.//sumario/diario')
        if diario is None:
            raise BormeDoesntExistException
        return diario.get('numero')
    elif root.tag == 'sumario':
        return tree.xpath('//sumario/diario')[0].attrib['nbo']
    else:
        raise BormeDoesntExistException


def get_url_pdfs_provincia(date, provincia, secure=USE_HTTPS):
    """ Obtiene las URLs para descargar los BORMEs de la provincia y fecha indicada """
    url = get_url_xml(date, secure=secure)
    req = requests.get(url, headers={'Accept': 'application/xml'})
    content = req.content
    tree = etree.fromstring(content).getroottree()

    root = tree.getroot()
    urls = {}
    if root.tag == 'response':
        status = root.find('status/code')
        if status is not None and status.text != '200':
            raise BormeDoesntExistException
        for item in root.findall('.//sumario/diario/seccion/item'):
            prov = item.find('titulo').text
            if prov != provincia:
                continue
            url_pdf = item.find('url_pdf').text
            seccion = item.getparent().get('codigo')
            urls[seccion] = url_pdf
    elif root.tag == 'sumario':
        protocol = 'https' if secure else 'http'
        url_base = URL_BASE % protocol
        for item in tree.xpath('//sumario/diario/seccion/emisor/item'):
            prov = item.xpath('titulo')[0].text
            if prov != provincia:
                continue
            url = url_base + item.xpath('urlPdf')[0].text
            seccion = item.getparent().getparent().get('num')
            urls[seccion] = url
    else:
        raise BormeDoesntExistException

    return urls


def get_url_pdfs_seccion(date, seccion, secure=USE_HTTPS):
    """
    Obtiene las URLs para descargar los BORMEs de la seccion y fecha indicada

    {'A CORUÑA': 'https://www.boe.es/borme/dias/2016/04/20/pdfs/BORME-A-2016-75-15.pdf',
     'ALBACETE': 'https://www.boe.es/borme/dias/2016/04/20/pdfs/BORME-A-2016-75-02.pdf',
    }
    """

    if seccion not in (SECCION.A, SECCION.B):
        raise ValueError('Section must be: A or B')

    url = get_url_xml(date, secure=secure)
    req = requests.get(url, headers={'Accept': 'application/xml'})
    content = req.content
    tree = etree.fromstring(content).getroottree()

    root = tree.getroot()
    urls = {}

    if root.tag == 'response':
        status = root.find('status/code')
        if status is not None and status.text != '200':
            raise BormeDoesntExistException
        for item in root.findall('.//sumario/diario/seccion[@codigo="{}"]/item'.format(seccion)):
            provincia = item.find('titulo').text
            urls[provincia] = item.find('url_pdf').text
    elif root.tag == 'sumario':
        protocol = 'https' if secure else 'http'
        url_base = URL_BASE % protocol
        for item in tree.xpath('//sumario/diario/seccion[@num="{}"]/emisor/item'.format(seccion)):
            provincia = item.xpath('titulo')[0].text
            url = url_base + item.xpath('urlPdf')[0].text
            urls[provincia] = url
    else:
        raise BormeDoesntExistException

    return urls


def get_url_seccion_c(date, format='xml', secure=USE_HTTPS):
    """
    Obtiene las URLs para descargar los BORMEs de la seccion C y formato y fecha indicada
    """
    url = get_url_xml(date, secure=secure)
    req = requests.get(url, headers={'Accept': 'application/xml'})
    content = req.content
    tree = etree.fromstring(content).getroottree()

    root = tree.getroot()
    urls = {}

    if root.tag == 'response':
        status = root.find('status/code')
        if status is not None and status.text != '200':
            raise BormeDoesntExistException
        format_map = {'xml': 'url_xml', 'htm': 'url_html', 'html': 'url_html', 'pdf': 'url_pdf'}
        format_tag = format_map.get(format)
        if not format_tag:
            raise ValueError('format must be "xml", "htm" or "pdf"')
        for apartado in root.findall('.//sumario/diario/seccion[@codigo="C"]/apartado'):
            emisor = apartado.get('nombre')
            urls[emisor] = {}
            for item in apartado.findall('item'):
                titulo = item.find('titulo').text
                url_elem = item.find(format_tag)
                if url_elem is not None:
                    urls[emisor][titulo] = url_elem.text
    elif root.tag == 'sumario':
        format_map_old = {'xml': 'urlXml', 'htm': 'urlHtm', 'html': 'urlHtm', 'pdf': 'urlPdf'}
        format_tag = format_map_old.get(format)
        if not format_tag:
            raise ValueError('format must be "xml", "htm" or "pdf"')
        protocol = 'https' if secure else 'http'
        url_base = URL_BASE % protocol
        for item_emisor in tree.xpath('//sumario/diario/seccion[@num="C"]/emisor'):
            emisor = item_emisor.get('nombre')
            urls[emisor] = {}
            for item in item_emisor.xpath('item'):
                titulo = item.xpath('titulo')[0].text
                url = url_base + item.xpath(format_tag)[0].text
                urls[emisor][titulo] = url
    else:
        raise BormeDoesntExistException

    return urls


def get_url_pdfs(date, seccion=None, provincia=None, secure=USE_HTTPS):
    if seccion and not provincia:
        urls = get_url_pdfs_seccion(date, seccion, secure=secure)
    elif provincia and not seccion:
        urls = get_url_pdfs_provincia(date, provincia, secure=secure)
    elif provincia and seccion:
        raise NotImplementedError
    else:
        raise AttributeError('You must specifiy either provincia or seccion or both')
    return urls


# date = (year, month, date) or datetime.date
def get_url_xml(date, secure=USE_HTTPS):
    """ Obtiene el archivo XML que contiene las URLs de los BORMEs del dia indicado """
    if isinstance(date, tuple):
        date = datetime.date(year=date[0], month=date[1], day=date[2])

    return BORME_XML_URL.format(year=date.year, month=date.month, day=date.day)


def download_url(url, filename=None, try_again=0, forcedownload=False, headers=None):
    logger.debug('Downloading URL: %s' % url)
    if os.path.exists(filename):
        if forcedownload:
            logger.debug('%s already exists, but forcing download!' % os.path.basename(filename))
        else:
            logger.debug('%s already exists!' % os.path.basename(filename))
            return False
    try:
        req = requests.get(url, stream=True, headers=headers)
    except Exception as e:
        logger.warning('%s failed to download (%d time)!' % (url, try_again + 1))
        if try_again < 3:
            return download_url(url, filename=filename, try_again=try_again+1, forcedownload=forcedownload, headers=headers)
        else:
            raise e

    with open(filename, "wb") as fp:
        for chunk in req.iter_content(chunk_size=1024):
            if chunk:
                fp.write(chunk)

    if 'content-length' in req.headers:
        content_length = req.headers['content-length']
        logger.debug("%.2f KB" % (int(content_length) / 1024.0))

    return True


def download_urls(urls, path, forcedownload=False):
    """
        Descarga las urls a path indicado.
        Devuelve la lista de archivos que fueron descargados.
    """
    files = []
    for url in urls.values():
        filename = url.split('/')[-1]
        full_path = os.path.join(path, filename)
        downloaded = download_url(url, full_path, forcedownload=forcedownload)

        if downloaded:
            files.append(full_path)
            logger.info('Downloaded %s' % filename)

        #assert os.path.exists(filepdf)
        #assert os.path.getsize(filepdf) == int(url.attrib['szBytes'])
    return files


def download_urls_multi(urls, path, forcedownload=False, threads=THREADS):
    """
        Descarga las urls a path indicado (versión multihilo).
        urls: {_: url}
        Devuelve la lista de archivos que fueron descargados.
    """

    q = Queue()
    files = []

    for i in range(THREADS):
        t = ThreadDownloadUrl(i, q, files)
        t.setDaemon(True)
        t.start()

    for url in urls.values():
        filename = url.split('/')[-1]
        full_path = os.path.join(path, filename)
        q.put((url, full_path, forcedownload))

    q.join()
    return files


def download_urls_multi_names(urls, path, forcedownload=False, threads=THREADS):
    """
        Descarga las urls al path indicado (versión multihilo).
        urls: {filename: url}
        Devuelve la lista de archivos que fueron descargados.
    """

    q = Queue()
    files = []

    for i in range(THREADS):
        t = ThreadDownloadUrl(i, q, files)
        t.setDaemon(True)
        t.start()

    for filename, url in urls.items():
        full_path = os.path.join(path, filename)
        q.put((url, full_path, forcedownload))

    q.join()
    return files


class ThreadDownloadUrl(Thread):
    """Threaded Url Grab"""
    def __init__(self, thread_id, queue, files):
        super(ThreadDownloadUrl, self).__init__()
        self.thread_id = thread_id
        self.queue = queue
        self.files = files

    def run(self):
        while True:
            url, full_path, forcedownload = self.queue.get()
            time.sleep(0.6)
            downloaded = download_url(url, full_path, forcedownload=forcedownload)

            if downloaded:
                self.files.append(full_path)
                logger.info('Downloaded %s' % os.path.basename(full_path))

            self.queue.task_done()
