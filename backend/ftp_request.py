import traceback, time, sys, logging
from time import timezone
from binascii import hexlify
from datetime import datetime
from os import walk
import glob, os, shutil, time
from ftplib import FTP, error_perm

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from sqlalchemy import Table, Column, MetaData, create_engine, PickleType, Integer, String, JSON, Boolean
from sqlalchemy.pool import NullPool

import mussond, logmusson


print = logmusson.logger.info

def FtpUpload(ftp_dir='/tmp/ftp/', arc_subdir='_arch', *arg, **kwarg):
    try:
        logging.info('FtpRequest > ftp_dir:{},arc_subdir:{}'.format(ftp_dir,arc_subdir))
        for (dirpath, dirnames, filenames) in walk(ftp_dir):
            if os.path.basename(dirpath) != arc_subdir:
                for filename in filenames:
                    if os.path.splitext(filename)[1] == '.zip':
                        #print(dirpath+'/'+filename)
                        shutil.unpack_archive(dirpath+'/'+filename, dirpath+'/' )
                        if os.path.isfile(dirpath + '/' + arc_subdir + '/' + filename):
                            os.remove(dirpath + '/' + arc_subdir + '/' + filename)
                        shutil.move(dirpath+'/'+filename, dirpath+'/'+arc_subdir)
        engine = create_engine(mussond.enter, poolclass=NullPool, connect_args={'options': '-csearch_path={}'.format('osi'), 'connect_timeout': 5})
        session = Session(engine)
        for (dirpath, dirnames, filenames) in walk(ftp_dir):
            if os.path.basename(dirpath) != arc_subdir:
                for filename in filenames:
                    if os.path.splitext(filename)[1] == '.rmon' or os.path.splitext(filename)[1] == '.pmon':
                        #print(dirpath+'/'+filename)
                        s = {}
                        query = ''
                        try:
                            with open(dirpath+'/'+filename) as f:
                                f.seek(0,0)
                                fstring = f.readline()
                                if fstring=='':
                                    logging.error('!!! fstring IS EMPTY !!!')
                                    f.seek(0, 0)
                                    logging.error(f.readlines())
                        except IOError:
                            logging.error(sys.exc_info())
                            logging.error("File not accessible")
                        print(filename+': '+fstring)
                        norm=True
                        s['filename'] = dirpath + '/' + filename
                        try:
                            a,s['ip'],a,s['slot'],s['facility'],s['pmon_rmon'],interv,s['date'] = fstring.split(",")
                        except ValueError:
                            logging.error(dirpath+'/'+filename+' fstring >> "'+fstring+'"')
                            logging.error(sys.exc_info())
                            print('ERROR FTP HEADER VALUE !!!')
                            norm=False
                        if norm:
                            s['date']= s['date'].strip('\n')
                            if interv == '15min':
                                s['interval']=15
                            elif  interv == '1day':
                                s['interval']=1440
                            print(s)
                            if s['pmon_rmon']=='RMON':
                                query="call osi.up_ftp_rmon_insert('{}','{}','{}','{}','{}')".\
                                    format(s['filename'],s['ip'],s['date'],s['slot'], s['interval'])
                            elif s['pmon_rmon'] == 'PMON' and s['facility']=='RF':
                                query = "call osi.up_ftp_pmon_insert('{}','{}','{}','{}','{}')". \
                                    format(s['filename'], s['ip'], s['date'], s['slot'], s['interval'])
                            if query != '':
                                print(query)
                                session.execute(query)
                                session.commit()
                        print('MOVE '+s['filename']+'>>>'+ dirpath+'/'+arc_subdir)
                        if os.path.isfile(dirpath+'/'+arc_subdir+'/'+filename):
                            os.remove(dirpath+'/'+arc_subdir+'/'+filename)
                        shutil.move(s['filename'], dirpath+'/'+arc_subdir)
        logging.info('succeded')
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file=open(logmusson.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        session.close()
        engine.dispose()
    return ''

#call osi.up_ftp_rmon_insert('/tmp/ftp/192.168.20.50/15min-ETH-s8p1-20210331.rmon', '192.168.20.50', '2021/03/31', 'SLOT-8/PORT-1', '15')
#call osi.up_ftp_pmon_insert('/tmp/ftp/192.168.20.50/15min-RF-s9p1-20210331.pmon', '192.168.20.50', '2021/03/31', 'SLOT-9/PORT-1', '15')

#FtpSync(ip='192.168.20.50',pwd='mus654321',lgn='musson')

def FtpSync(ftp_dir='/tmp/ftp/',arc_subdir='_arch',ip='192.168.43.108',pwd='',lgn='',timeout=10, flow=0, ne_id=0, *arg,**kwarg):
    try:
        rescode = 0
        logging.info('FtpSync > ftp_dir:{},arc_subdir:{},ip:{},'.format(ftp_dir,arc_subdir,ip))

        if not os.path.isdir(ftp_dir):
            os.makedirs(ftp_dir)
        if not os.path.isdir(ftp_dir+ip+'/'):
            os.makedirs(ftp_dir+ip+'/')
        if not os.path.isdir(ftp_dir+ip+'/'+arc_subdir+'/'):
            os.makedirs(ftp_dir+ip+'/'+arc_subdir+'/')

        # ftp = FTP(host='192.168.20.50', user='musson', passwd='mus654321', timeout=5)
        ftp = FTP(host=ip, user=lgn, passwd=pwd, timeout=timeout)
        for remote_dir in ['pmon','rmon']:
            ftp.cwd('/export/'+remote_dir)
            filenames = ftp.nlst()
            for filename in filenames:
                #print(filename)
                if os.path.splitext(filename)[1] == '.zip':
                    if not (os.path.isfile(ftp_dir+ip+'/'+filename) or os.path.isfile(ftp_dir+ip+'/'+arc_subdir+'/'+filename)) :
                        print('DOWNLOAD>>>>'+filename)
                        with open(ftp_dir+ip+'/'+filename, 'wb') as f:
                            ftp.retrbinary('RETR '+filename, f.write)
                elif os.path.splitext(filename)[1] == '.pmon' or os.path.splitext(filename)[1] == '.rmon':
                    is_in_ftp_dir = os.path.isfile(ftp_dir+ip+'/'+filename)
                    is_in_arc_subdir = os.path.isfile(ftp_dir+ip+'/'+arc_subdir+'/'+filename)
                    if not (is_in_ftp_dir or is_in_arc_subdir) :
                        print('DOWNLOAD>>>>'+filename)
                        with open(ftp_dir+ip+'/'+filename, 'wb') as f:
                            ftp.retrbinary('RETR '+filename, f.write)
                    else:
                        ftp_size = ftp.size(filename)
                        print(filename + '   ' + str(ftp_size))
                        if is_in_ftp_dir:
                            loc_size = os.path.getsize(ftp_dir+ip+'/'+filename)
                            #print(filename + '   ' + str(loc_size))
                        elif is_in_arc_subdir:
                            loc_size = os.path.getsize(ftp_dir+ip+'/'+arc_subdir+'/'+filename)
                            #print(filename + ' (ARC)  ' + str(loc_size))
                        if ftp_size != loc_size :
                            print('DOWNLOAD>>>>'+filename)
                            with open(ftp_dir + ip + '/' + filename, 'wb') as f:
                                ftp.retrbinary('RETR ' + filename, f.write)
        logging.info('succeded')
    except Exception as e:
        rescode = 200
        if e.__class__ == ConnectionRefusedError:
            rescode = 204
        elif e.__class__ == error_perm:
            if e.__str__() == '530 User cannot log in.':
                rescode = 230
            elif e.__str__() == '530 Permission denied.':
                rescode = 231
            elif e.__str__() == '550 The system cannot find the path specified. ':
                rescode = 250
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file=open(logmusson.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    return rescode

def FtpSyncRescode(code):
    value = {0:'success',
             204: 'connection refused error',
             230: 'user cannot log in',
             231: 'permission denied',
             250: 'path not found'}
    return value.get(code,'rescode not exists')

#print(FtpSync('192.168.43.108'))
#FtpSync(ip='192.168.20.50')
