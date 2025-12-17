#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор тестовых EML-файлов для ВКР
"Разработка системы автоматического анализа электронных писем"

Создает 10 писем: 5 легитимных + 5 подозрительных/фишинговых
Автор: Авсейцева Дарья Алексеевна
Финансовый университет при Правительстве РФ
"""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import random
import os


class EmailGenerator:
    """Генератор тестовых электронных писем в формате EML"""
    
    def __init__(self, output_dir='test_emails'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def create_email(
        self,
        subject,
        body_text,
        body_html,
        from_addr,
        from_name,
        to_addr,
        reply_to=None,
        spf_result='pass',
        dkim_result='pass',
        dmarc_result='pass',
        add_suspicious_urls=False,
        message_id_domain=None,
        received_from_ip='185.86.151.11',
        date_offset_days=0
    ):
        """
        Создает email-сообщение с заданными параметрами
        
        Args:
            subject: Тема письма
            body_text: Текстовое содержимое
            body_html: HTML содержимое
            from_addr: Email отправителя
            from_name: Имя отправителя
            to_addr: Email получателя
            reply_to: Адрес для ответа (если отличается от from_addr)
            spf_result: Результат SPF проверки (pass/fail/softfail/neutral)
            dkim_result: Результат DKIM проверки (pass/fail)
            dmarc_result: Результат DMARC проверки (pass/fail)
            add_suspicious_urls: Добавить подозрительные ссылки в текст
            message_id_domain: Домен для Message-ID
            received_from_ip: IP-адрес отправителя
            date_offset_days: Смещение даты письма (в днях от текущей)
        """
        msg = MIMEMultipart('alternative')
        
        # Основные заголовки
        msg['Subject'] = subject
        msg['From'] = f'{from_name} <{from_addr}>'
        msg['To'] = to_addr
        
        # Дата с возможным смещением
        email_date = datetime.now() - timedelta(days=date_offset_days)
        msg['Date'] = email_date.strftime('%a, %d %b %Y %H:%M:%S +0300')
        
        # Message-ID
        if not message_id_domain:
            message_id_domain = from_addr.split('@')[1]
        timestamp = int(email_date.timestamp())
        random_str = ''.join(random.choices('0123456789abcdef', k=16))
        msg['Message-ID'] = f'<{random_str}.{timestamp}@{message_id_domain}>'
        
        # Reply-To (признак фишинга если отличается)
        if reply_to:
            msg['Reply-To'] = reply_to
        
        # Authentication-Results
        auth_results = (
            f'mx.google.com; '
            f'spf={spf_result} smtp.mailfrom={from_addr.split("@")[1]}; '
            f'dkim={dkim_result} header.i=@{from_addr.split("@")[1]}; '
            f'dmarc={dmarc_result} header.from={from_addr.split("@")[1]}'
        )
        msg['Authentication-Results'] = auth_results
        
        # Received headers (цепочка маршрутизации)
        received_date = email_date.strftime('%a, %d %b %Y %H:%M:%S +0300')
        msg['Received'] = (
            f'from mail.{from_addr.split("@")[1]} ({received_from_ip}) '
            f'by mx.google.com with ESMTPS id {random_str[:10]}; '
            f'{received_date}'
        )
        
        # Return-Path
        msg['Return-Path'] = f'<{from_addr}>'
        
        # Добавляем текстовую и HTML части
        text_part = MIMEText(body_text, 'plain', 'utf-8')
        html_part = MIMEText(body_html, 'html', 'utf-8')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        return msg
    
    def save_email(self, msg, filename):
        """Сохраняет email в файл формата EML"""
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(msg.as_string())
        return filepath


def generate_legitimate_emails(generator):
    """Генерирует 5 легитимных писем"""
    
    emails = []
    
    # 1. Банковская выписка
    emails.append({
        'subject': 'Выписка по счёту за декабрь 2024',
        'body_text': '''Уважаемый клиент!

Направляем вам ежемесячную выписку по банковскому счёту за период с 01.12.2024 по 17.12.2024.

Номер счёта: 40817810099910004312
Остаток на начало периода: 150 000,00 ₽
Поступления: 85 000,00 ₽
Списания: 87 680,00 ₽
Остаток на конец периода: 147 320,00 ₽

Детальную выписку вы можете получить в мобильном приложении или в личном кабинете на сайте банка.

С уважением,
Служба информирования клиентов
ПАО "Сбербанк России"

Это автоматическое сообщение. Пожалуйста, не отвечайте на него.''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<h2 style="color: #21a038;">Выписка по счёту</h2>
<p>Уважаемый клиент!</p>
<p>Направляем вам ежемесячную выписку по банковскому счёту за период с <strong>01.12.2024</strong> по <strong>17.12.2024</strong>.</p>
<table style="border-collapse: collapse; margin: 20px 0;">
<tr><td style="padding: 8px; border: 1px solid #ddd;">Номер счёта:</td><td style="padding: 8px; border: 1px solid #ddd;">40817810099910004312</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;">Остаток на начало:</td><td style="padding: 8px; border: 1px solid #ddd;">150 000,00 ₽</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;">Поступления:</td><td style="padding: 8px; border: 1px solid #ddd; color: green;">+85 000,00 ₽</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;">Списания:</td><td style="padding: 8px; border: 1px solid #ddd; color: red;">-87 680,00 ₽</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Остаток на конец:</strong></td><td style="padding: 8px; border: 1px solid #ddd;"><strong>147 320,00 ₽</strong></td></tr>
</table>
<p>Детальную выписку вы можете получить в мобильном приложении или в <a href="https://online.sberbank.ru">личном кабинете</a>.</p>
<hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
<p style="color: #666; font-size: 12px;">С уважением,<br>Служба информирования клиентов<br>ПАО "Сбербанк России"</p>
<p style="color: #999; font-size: 11px;">Это автоматическое сообщение. Пожалуйста, не отвечайте на него.</p>
</body></html>''',
        'from_addr': 'noreply@sberbank.ru',
        'from_name': 'Сбербанк Онлайн',
        'to_addr': 'customer@example.ru',
        'spf_result': 'pass',
        'dkim_result': 'pass',
        'dmarc_result': 'pass',
        'received_from_ip': '194.67.23.45',
        'date_offset_days': 1
    })
    
    # 2. Подтверждение заказа из интернет-магазина
    emails.append({
        'subject': 'Ваш заказ №987654 оформлен',
        'body_text': '''Здравствуйте!

Ваш заказ №987654 от 17.12.2024 успешно оформлен и принят в обработку.

Состав заказа:
- Ноутбук Lenovo ThinkPad E14 Gen 5 (1 шт.) - 75 990 ₽
- Мышь Logitech MX Master 3S (1 шт.) - 8 990 ₽

Итого к оплате: 84 980 ₽
Способ оплаты: Банковская карта (оплачено)

Ожидаемая дата доставки: 20-21 декабря 2024
Адрес доставки: Москва, ул. Большая Садовая, д. 10, кв. 25

Отследить статус заказа можно в личном кабинете: https://www.mvideo.ru/myorder

Спасибо за покупку!
Команда М.Видео''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
<div style="background: white; padding: 30px; border-radius: 8px;">
<img src="https://www.mvideo.ru/logo.png" alt="М.Видео" style="height: 40px;">
<h2 style="color: #e31e24; margin-top: 20px;">Заказ оформлен!</h2>
<p>Здравствуйте!</p>
<p>Ваш заказ <strong>№987654</strong> от 17.12.2024 успешно оформлен и принят в обработку.</p>
<div style="background: #f9f9f9; padding: 15px; margin: 20px 0; border-radius: 4px;">
<h3 style="margin-top: 0;">Состав заказа:</h3>
<p>• Ноутбук Lenovo ThinkPad E14 Gen 5 (1 шт.) - <strong>75 990 ₽</strong></p>
<p>• Мышь Logitech MX Master 3S (1 шт.) - <strong>8 990 ₽</strong></p>
<hr style="border: none; border-top: 1px solid #ddd; margin: 15px 0;">
<p><strong>Итого к оплате: 84 980 ₽</strong></p>
<p style="color: green;">✓ Оплачено банковской картой</p>
</div>
<p><strong>Ожидаемая дата доставки:</strong> 20-21 декабря 2024</p>
<p><strong>Адрес доставки:</strong> Москва, ул. Большая Садовая, д. 10, кв. 25</p>
<p style="margin-top: 30px;">
<a href="https://www.mvideo.ru/myorder" style="display: inline-block; padding: 12px 30px; background: #e31e24; color: white; text-decoration: none; border-radius: 4px;">Отследить заказ</a>
</p>
<p style="color: #666; font-size: 14px; margin-top: 30px;">Спасибо за покупку!<br>Команда М.Видео</p>
</div>
</div>
</body></html>''',
        'from_addr': 'orders@mvideo.ru',
        'from_name': 'М.Видео',
        'to_addr': 'customer@example.ru',
        'spf_result': 'pass',
        'dkim_result': 'pass',
        'dmarc_result': 'pass',
        'received_from_ip': '213.180.193.56',
        'date_offset_days': 0
    })
    
    # 3. Корпоративное письмо
    emails.append({
        'subject': 'Напоминание о совещании 19.12.2024',
        'body_text': '''Добрый день, коллеги!

Напоминаю о запланированном совещании отдела информационных технологий.

Дата и время: 19 декабря 2024, 14:00
Место: Конференц-зал (3 этаж)
Длительность: 1,5 часа

Повестка дня:
1. Итоги квартала: выполнение KPI
2. Планирование бюджета на 2025 год
3. Обсуждение новых проектов
4. Разное

Просьба подготовить краткие отчёты по текущим проектам (5-7 минут на каждого).

Ссылка на онлайн-подключение (для удалённых сотрудников):
https://zoom.us/j/1234567890

С уважением,
Петров Дмитрий Александрович
Руководитель отдела ИТ
ООО "ТехноСервис"
+7 (495) 123-45-67 доб. 234''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif; line-height: 1.6;">
<p>Добрый день, коллеги!</p>
<p>Напоминаю о запланированном совещании отдела информационных технологий.</p>
<table style="margin: 20px 0; border-collapse: collapse;">
<tr><td style="padding: 8px; font-weight: bold;">Дата и время:</td><td style="padding: 8px;">19 декабря 2024, 14:00</td></tr>
<tr><td style="padding: 8px; font-weight: bold;">Место:</td><td style="padding: 8px;">Конференц-зал (3 этаж)</td></tr>
<tr><td style="padding: 8px; font-weight: bold;">Длительность:</td><td style="padding: 8px;">1,5 часа</td></tr>
</table>
<p><strong>Повестка дня:</strong></p>
<ol>
<li>Итоги квартала: выполнение KPI</li>
<li>Планирование бюджета на 2025 год</li>
<li>Обсуждение новых проектов</li>
<li>Разное</li>
</ol>
<p>Просьба подготовить краткие отчёты по текущим проектам (5-7 минут на каждого).</p>
<p>Ссылка на онлайн-подключение (для удалённых сотрудников):<br>
<a href="https://zoom.us/j/1234567890">https://zoom.us/j/1234567890</a></p>
<hr style="margin: 30px 0; border: none; border-top: 1px solid #ccc;">
<p style="color: #666;">
С уважением,<br>
<strong>Петров Дмитрий Александрович</strong><br>
Руководитель отдела ИТ<br>
ООО "ТехноСервис"<br>
+7 (495) 123-45-67 доб. 234
</p>
</body></html>''',
        'from_addr': 'd.petrov@technoservice.ru',
        'from_name': 'Петров Дмитрий',
        'to_addr': 'it-team@technoservice.ru',
        'spf_result': 'pass',
        'dkim_result': 'pass',
        'dmarc_result': 'pass',
        'received_from_ip': '192.168.10.25',
        'date_offset_days': 2
    })
    
    # 4. Новостная рассылка
    emails.append({
        'subject': 'РБК: главные новости дня – 17 декабря',
        'body_text': '''Главные новости дня

ЭКОНОМИКА
ЦБ сохранил ключевую ставку на уровне 16%
Центральный банк РФ на заседании совета директоров принял решение сохранить ключевую ставку на текущем уровне 16% годовых.

ТЕХНОЛОГИИ
Российская IT-компания представила новую платформу для бизнеса
Стартап из Сколково анонсировал облачную платформу для автоматизации бизнес-процессов с использованием искусственного интеллекта.

ФИНАНСЫ
Минфин разместил ОФЗ на 50 млрд рублей
Министерство финансов РФ успешно разместило облигации федерального займа на сумму 50 млрд рублей со средней доходностью 12,8%.

Читать полностью: https://www.rbc.ru/daily

---
Вы получили это письмо, так как подписаны на ежедневную рассылку РБК.
Отписаться от рассылки: https://www.rbc.ru/unsubscribe''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #002fa7; padding: 20px; text-align: center;">
<h1 style="color: white; margin: 0;">РБК</h1>
<p style="color: white; margin: 5px 0;">Главные новости дня – 17 декабря</p>
</div>
<div style="padding: 20px;">
<div style="margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px;">
<h2 style="color: #002fa7; margin-bottom: 10px;">ЭКОНОМИКА</h2>
<h3 style="margin-top: 0;">ЦБ сохранил ключевую ставку на уровне 16%</h3>
<p>Центральный банк РФ на заседании совета директоров принял решение сохранить ключевую ставку на текущем уровне 16% годовых.</p>
<a href="https://www.rbc.ru/economics/article1" style="color: #002fa7;">Читать далее →</a>
</div>
<div style="margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px;">
<h2 style="color: #002fa7; margin-bottom: 10px;">ТЕХНОЛОГИИ</h2>
<h3 style="margin-top: 0;">Российская IT-компания представила новую платформу для бизнеса</h3>
<p>Стартап из Сколково анонсировал облачную платформу для автоматизации бизнес-процессов с использованием искусственного интеллекта.</p>
<a href="https://www.rbc.ru/technology/article2" style="color: #002fa7;">Читать далее →</a>
</div>
<div style="margin-bottom: 30px;">
<h2 style="color: #002fa7; margin-bottom: 10px;">ФИНАНСЫ</h2>
<h3 style="margin-top: 0;">Минфин разместил ОФЗ на 50 млрд рублей</h3>
<p>Министерство финансов РФ успешно разместило облигации федерального займа на сумму 50 млрд рублей со средней доходностью 12,8%.</p>
<a href="https://www.rbc.ru/finances/article3" style="color: #002fa7;">Читать далее →</a>
</div>
<div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee;">
<p style="color: #666; font-size: 12px;">Вы получили это письмо, так как подписаны на ежедневную рассылку РБК.</p>
<a href="https://www.rbc.ru/unsubscribe" style="color: #666; font-size: 12px;">Отписаться от рассылки</a>
</div>
</div>
</body></html>''',
        'from_addr': 'newsletter@rbc.ru',
        'from_name': 'РБК Новости',
        'to_addr': 'customer@example.ru',
        'spf_result': 'pass',
        'dkim_result': 'pass',
        'dmarc_result': 'pass',
        'received_from_ip': '217.20.147.89',
        'date_offset_days': 0
    })
    
    # 5. Уведомление от Госуслуг
    emails.append({
        'subject': 'Уведомление о готовности документа',
        'body_text': '''Уважаемый пользователь!

Документ, запрошенный вами на портале Госуслуги, готов к получению.

Тип документа: Справка об отсутствии судимости
Номер заявления: 123456789012
Дата подачи: 10.12.2024
Статус: Готов к получению

Вы можете получить документ одним из способов:
1. В электронном виде в личном кабинете на портале gosuslugi.ru
2. В бумажном виде в отделении МВД по адресу: г. Москва, ул. Петровка, д. 38

Для получения документа в электронном виде войдите в личный кабинет:
https://www.gosuslugi.ru/

Настоящее электронное сообщение было сформировано автоматически. Отвечать на него не требуется.

С уважением,
Единый портал государственных и муниципальных услуг''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto; border: 2px solid #0d4cd3; border-radius: 8px; overflow: hidden;">
<div style="background: #0d4cd3; color: white; padding: 20px;">
<h2 style="margin: 0;">Госуслуги</h2>
<p style="margin: 5px 0 0 0; opacity: 0.9;">Уведомление о готовности документа</p>
</div>
<div style="padding: 30px;">
<p>Уважаемый пользователь!</p>
<p>Документ, запрошенный вами на портале Госуслуги, готов к получению.</p>
<table style="width: 100%; margin: 20px 0; border-collapse: collapse;">
<tr style="background: #f5f5f5;"><td style="padding: 10px; border: 1px solid #ddd;">Тип документа:</td><td style="padding: 10px; border: 1px solid #ddd;"><strong>Справка об отсутствии судимости</strong></td></tr>
<tr><td style="padding: 10px; border: 1px solid #ddd;">Номер заявления:</td><td style="padding: 10px; border: 1px solid #ddd;">123456789012</td></tr>
<tr style="background: #f5f5f5;"><td style="padding: 10px; border: 1px solid #ddd;">Дата подачи:</td><td style="padding: 10px; border: 1px solid #ddd;">10.12.2024</td></tr>
<tr><td style="padding: 10px; border: 1px solid #ddd;">Статус:</td><td style="padding: 10px; border: 1px solid #ddd; color: green;"><strong>✓ Готов к получению</strong></td></tr>
</table>
<p><strong>Вы можете получить документ одним из способов:</strong></p>
<ol>
<li>В электронном виде в личном кабинете на портале gosuslugi.ru</li>
<li>В бумажном виде в отделении МВД по адресу: г. Москва, ул. Петровка, д. 38</li>
</ol>
<div style="text-align: center; margin: 30px 0;">
<a href="https://www.gosuslugi.ru/" style="display: inline-block; padding: 15px 40px; background: #0d4cd3; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">Перейти в личный кабинет</a>
</div>
<hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
<p style="color: #666; font-size: 12px;">Настоящее электронное сообщение было сформировано автоматически. Отвечать на него не требуется.</p>
<p style="color: #666; font-size: 12px;">С уважением,<br>Единый портал государственных и муниципальных услуг</p>
</div>
</div>
</body></html>''',
        'from_addr': 'noreply@gosuslugi.ru',
        'from_name': 'Госуслуги',
        'to_addr': 'customer@example.ru',
        'spf_result': 'pass',
        'dkim_result': 'pass',
        'dmarc_result': 'pass',
        'received_from_ip': '188.128.41.23',
        'date_offset_days': 3
    })
    
    return emails


def generate_suspicious_emails(generator):
    """Генерирует 5 подозрительных/фишинговых писем"""
    
    emails = []
    
    # 1. Фишинг под банк с провалом SPF/DKIM/DMARC
    emails.append({
        'subject': '⚠️ СРОЧНО! Ваш счёт заблокирован',
        'body_text': '''ВНИМАНИЕ! ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ ДЕЙСТВИЕ!

Ваш банковский счёт временно заблокирован в связи с подозрительной активностью, обнаруженной нашей системой безопасности.

Дата блокировки: 17.12.2024
Причина: Подозрение на мошеннические операции
Номер инцидента: SEC-2024-98765

Для НЕМЕДЛЕННОЙ разблокировки счёта необходимо подтвердить вашу личность:

ПЕРЕЙДИТЕ ПО ССЫЛКЕ: http://sberbank-secure.tk/verify?id=123456789

ВАЖНО! Если вы не подтвердите данные в течение 24 ЧАСОВ, ваш счёт будет ОКОНЧАТЕЛЬНО ЗАБЛОКИРОВАН, а все средства переведены в резервный фонд банка!

Служба безопасности
ПАО Сбербанк''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto; border: 3px solid #ff0000;">
<div style="background: #ff0000; color: white; padding: 20px; text-align: center;">
<h1 style="margin: 0; font-size: 24px;">⚠️ СРОЧНОЕ УВЕДОМЛЕНИЕ</h1>
</div>
<div style="padding: 30px; background: #fff3cd;">
<p style="color: #721c24; font-size: 18px; font-weight: bold;">ВНИМАНИЕ! ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ ДЕЙСТВИЕ!</p>
<p>Ваш банковский счёт <span style="background: yellow;">временно заблокирован</span> в связи с подозрительной активностью, обнаруженной нашей системой безопасности.</p>
<table style="width: 100%; margin: 20px 0; background: white;">
<tr><td style="padding: 10px; border: 1px solid #ddd;">Дата блокировки:</td><td style="padding: 10px; border: 1px solid #ddd;"><strong>17.12.2024</strong></td></tr>
<tr><td style="padding: 10px; border: 1px solid #ddd;">Причина:</td><td style="padding: 10px; border: 1px solid #ddd; color: red;"><strong>Подозрение на мошеннические операции</strong></td></tr>
<tr><td style="padding: 10px; border: 1px solid #ddd;">Номер инцидента:</td><td style="padding: 10px; border: 1px solid #ddd;">SEC-2024-98765</td></tr>
</table>
<p style="font-size: 16px;">Для <strong>НЕМЕДЛЕННОЙ</strong> разблокировки счёта необходимо подтвердить вашу личность:</p>
<div style="text-align: center; margin: 30px 0;">
<a href="http://sberbank-secure.tk/verify?id=123456789" style="display: inline-block; padding: 20px 50px; background: #21a038; color: white; text-decoration: none; font-size: 18px; font-weight: bold; border-radius: 4px; animation: blink 1s infinite;">ПОДТВЕРДИТЬ ДАННЫЕ</a>
</div>
<div style="background: #ff0000; color: white; padding: 15px; margin: 20px 0; border-radius: 4px;">
<p style="margin: 0; font-weight: bold;">⏰ ВАЖНО! Если вы не подтвердите данные в течение 24 ЧАСОВ, ваш счёт будет ОКОНЧАТЕЛЬНО ЗАБЛОКИРОВАН!</p>
</div>
<p style="color: #666; font-size: 12px; margin-top: 30px;">Служба безопасности<br>ПАО Сбербанк</p>
</div>
</div>
</body></html>''',
        'from_addr': 'security@sberbank.ru',
        'from_name': 'Служба Безопасности Сбербанк',
        'to_addr': 'victim@example.ru',
        'reply_to': 'phishing@evil-domain.tk',  # Несоответствие!
        'spf_result': 'fail',  # ПРОВАЛ SPF
        'dkim_result': 'fail',  # ПРОВАЛ DKIM
        'dmarc_result': 'fail',  # ПРОВАЛ DMARC
        'received_from_ip': '45.142.212.61',  # Подозрительный IP
        'message_id_domain': 'suspicious-mail-server.tk',
        'date_offset_days': 0
    })
    
    # 2. BEC (Business Email Compromise) - имитация руководителя
    emails.append({
        'subject': 'Re: Срочный перевод',
        'body_text': '''Добрый день!

Мне срочно нужно сделать оплату поставщику, но у меня сейчас нет доступа к банк-клиенту.

Можете перевести 450 000 рублей на следующие реквизиты:

ООО "ТехноСнаб"
ИНН: 7743215689
Р/с: 40702810100000098765
Банк: АО "Альфа-Банк"
БИК: 044525593
Назначение: Оплата по договору №456/2024

Это очень срочно, нужно сделать до конца дня. Договор прикреплен в архиве:
https://dropbox-files.bit.ly/contract_456.zip

Отчитайтесь, когда переведете.

Петров Д.А.
Генеральный директор''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<p>Добрый день!</p>
<p>Мне срочно нужно сделать оплату поставщику, но у меня сейчас нет доступа к банк-клиенту.</p>
<p>Можете перевести <strong style="color: red;">450 000 рублей</strong> на следующие реквизиты:</p>
<div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-left: 4px solid #333;">
<p style="margin: 5px 0;"><strong>ООО "ТехноСнаб"</strong></p>
<p style="margin: 5px 0;">ИНН: 7743215689</p>
<p style="margin: 5px 0;">Р/с: 40702810100000098765</p>
<p style="margin: 5px 0;">Банк: АО "Альфа-Банк"</p>
<p style="margin: 5px 0;">БИК: 044525593</p>
<p style="margin: 5px 0;">Назначение: Оплата по договору №456/2024</p>
</div>
<p><strong>Это очень срочно</strong>, нужно сделать до конца дня. Договор прикреплен в архиве:</p>
<p><a href="https://dropbox-files.bit.ly/contract_456.zip" style="color: #0066cc;">https://dropbox-files.bit.ly/contract_456.zip</a></p>
<p>Отчитайтесь, когда переведете.</p>
<p style="margin-top: 30px;">Петров Д.А.<br>Генеральный директор</p>
</body></html>''',
        'from_addr': 'd.petrov@technoservice.ru',  # Выглядит легитимно
        'from_name': 'Петров Дмитрий',
        'to_addr': 'accountant@technoservice.ru',
        'reply_to': 'attacker@evil.com',  # НО Reply-To другой!
        'spf_result': 'softfail',  # Мягкий провал
        'dkim_result': 'fail',
        'dmarc_result': 'fail',
        'received_from_ip': '185.220.101.45',
        'date_offset_days': 1
    })
    
    # 3. Фишинг под доставку с коротким URL
    emails.append({
        'subject': 'Посылка ожидает получения на складе',
        'body_text': '''Уважаемый клиент!

Ваша посылка №RU789456123CN прибыла на склад в Москве.

Отправитель: AliExpress
Вес: 2.3 кг
Статус: Ожидает оплаты таможенного сбора

Для получения посылки необходимо оплатить таможенный сбор в размере 387 рублей.

Оплатить сбор: http://bit.ly/customs-pay-ru

После оплаты посылка будет доставлена в течение 2-3 рабочих дней. Если оплата не поступит в течение 5 дней, посылка будет возвращена отправителю.

Отследить посылку: http://tinyurl.com/track-package-ru

Почта России
Автоматическое уведомление''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #003d7a; color: white; padding: 20px;">
<h2 style="margin: 0;">Почта России</h2>
</div>
<div style="padding: 30px; background: white; border: 1px solid #ddd;">
<p>Уважаемый клиент!</p>
<p>Ваша посылка <strong>№RU789456123CN</strong> прибыла на склад в Москве.</p>
<table style="width: 100%; margin: 20px 0;">
<tr style="background: #f5f5f5;"><td style="padding: 10px;">Отправитель:</td><td style="padding: 10px;"><strong>AliExpress</strong></td></tr>
<tr><td style="padding: 10px;">Вес:</td><td style="padding: 10px;">2.3 кг</td></tr>
<tr style="background: #f5f5f5;"><td style="padding: 10px;">Статус:</td><td style="padding: 10px; color: orange;"><strong>⏳ Ожидает оплаты таможенного сбора</strong></td></tr>
</table>
<div style="background: #fff3cd; padding: 15px; margin: 20px 0; border-left: 4px solid #ffc107;">
<p style="margin: 0;">Для получения посылки необходимо оплатить таможенный сбор в размере <strong>387 рублей</strong>.</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="http://bit.ly/customs-pay-ru" style="display: inline-block; padding: 15px 40px; background: #ff9800; color: white; text-decoration: none; font-weight: bold; border-radius: 4px;">ОПЛАТИТЬ СБОР</a>
</div>
<p style="font-size: 14px;">После оплаты посылка будет доставлена в течение 2-3 рабочих дней.</p>
<p style="color: red; font-size: 14px;">⚠️ Если оплата не поступит в течение 5 дней, посылка будет возвращена отправителю.</p>
<p style="margin-top: 20px;"><a href="http://tinyurl.com/track-package-ru" style="color: #003d7a;">Отследить посылку →</a></p>
<hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
<p style="color: #666; font-size: 12px;">Почта России<br>Автоматическое уведомление</p>
</div>
</body></html>''',
        'from_addr': 'info@pochta.ru',
        'from_name': 'Почта России',
        'to_addr': 'victim@example.ru',
        'reply_to': 'scam@fake-delivery.com',
        'spf_result': 'neutral',
        'dkim_result': 'fail',
        'dmarc_result': 'fail',
        'received_from_ip': '91.234.56.78',
        'date_offset_days': 2
    })
    
    # 4. Фишинг с имитацией налоговой службы
    emails.append({
        'subject': 'Уведомление о задолженности по налогам',
        'body_text': '''Уважаемый налогоплательщик!

Федеральная Налоговая Служба информирует вас о наличии задолженности по налоговым платежам.

ИНН: 773456789012
Тип налога: НДФЛ за 2023 год
Сумма задолженности: 15 430 рублей
Пени: 847 рублей
Итого к оплате: 16 277 рублей

Просрочка составляет 45 дней. В соответствии со статьей 75 НК РФ при непогашении задолженности в течение 10 дней будет начато принудительное взыскание через судебных приставов.

Для оплаты задолженности online перейдите по ссылке:
https://nalog-oplata.ru/pay?inn=773456789012

Детальная информация о начислениях доступна в личном кабинете:
https://cabinet-nalog.site/login

При возникновении вопросов обращайтесь по телефону 8-800-222-2222

ФНС России''',
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto;">
<div style="background: #d32f2f; color: white; padding: 20px;">
<h2 style="margin: 0;">⚠️ Федеральная Налоговая Служба</h2>
<p style="margin: 5px 0 0 0;">Уведомление о задолженности</p>
</div>
<div style="padding: 30px; background: white; border: 2px solid #d32f2f;">
<p>Уважаемый налогоплательщик!</p>
<p>Федеральная Налоговая Служба информирует вас о наличии <strong style="color: red;">задолженности</strong> по налоговым платежам.</p>
<table style="width: 100%; margin: 20px 0; border-collapse: collapse;">
<tr style="background: #ffebee;"><td style="padding: 12px; border: 1px solid #ddd;">ИНН:</td><td style="padding: 12px; border: 1px solid #ddd;"><strong>773456789012</strong></td></tr>
<tr><td style="padding: 12px; border: 1px solid #ddd;">Тип налога:</td><td style="padding: 12px; border: 1px solid #ddd;">НДФЛ за 2023 год</td></tr>
<tr style="background: #ffebee;"><td style="padding: 12px; border: 1px solid #ddd;">Сумма задолженности:</td><td style="padding: 12px; border: 1px solid #ddd;"><strong>15 430 рублей</strong></td></tr>
<tr><td style="padding: 12px; border: 1px solid #ddd;">Пени:</td><td style="padding: 12px; border: 1px solid #ddd;">847 рублей</td></tr>
<tr style="background: #ffcdd2;"><td style="padding: 12px; border: 1px solid #ddd;"><strong>Итого к оплате:</strong></td><td style="padding: 12px; border: 1px solid #ddd;"><strong style="font-size: 18px; color: red;">16 277 рублей</strong></td></tr>
</table>
<div style="background: #fff9c4; padding: 15px; margin: 20px 0; border-left: 4px solid #fbc02d;">
<p style="margin: 0;"><strong>Просрочка составляет 45 дней.</strong> В соответствии со статьей 75 НК РФ при непогашении задолженности в течение <strong>10 дней</strong> будет начато принудительное взыскание через судебных приставов.</p>
</div>
<div style="text-align: center; margin: 30px 0;">
<a href="https://nalog-oplata.ru/pay?inn=773456789012" style="display: inline-block; padding: 15px 40px; background: #ff5722; color: white; text-decoration: none; font-weight: bold; border-radius: 4px; font-size: 16px;">ОПЛАТИТЬ ЗАДОЛЖЕННОСТЬ</a>
</div>
<p>Детальная информация о начислениях доступна в <a href="https://cabinet-nalog.site/login" style="color: #d32f2f;">личном кабинете</a>.</p>
<p style="margin-top: 30px; color: #666; font-size: 12px;">При возникновении вопросов обращайтесь по телефону <strong>8-800-222-2222</strong></p>
<p style="color: #666; font-size: 12px;">ФНС России</p>
</div>
</div>
</body></html>''',
        'from_addr': 'info@nalog.ru',
        'from_name': 'ФНС России',
        'to_addr': 'victim@example.ru',
        'reply_to': 'scammer@phishing-tax.com',
        'spf_result': 'fail',
        'dkim_result': 'fail',
        'dmarc_result': 'fail',
        'received_from_ip': '185.244.45.67',
        'message_id_domain': 'fake-nalog-server.com',
        'date_offset_days': 1
    })
    
    # 5. Криптовалютный скам с орфографическими ошибками
    emails.append({
        'subject': 'Вы выйграли 0.5 BTC в акции!',  # Орфографическая ошибка!
        'body_text': '''Поздровляем!

Ваш email адресс был случайно выбран в международной акции от биржи Binance!

Приз: 0.5 Bitcoin (₿0.5)
Текущая стоймость: ~$21,500 USD

Что бы получить выйгрыш, вам необходимо:

1. Перейти на страницу активаци приза:
   https://binance-promo.site/claim?id=BTC500

2. Ввести свой email и создать валет

3. Для активации приза необходимо внести комисию 0.001 BTC (около $43 USD) на обработку транзакции

Внимание! Срок действия приза - 48 часов с момента получения письма.

Ссылка для регистрации: http://bit.ly/binance-btc-win

С увожением,
Команда Binance Support''',  # Орфографические ошибки повсюду!
        'body_html': '''<html><body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #f6d365 0%, #fda085 100%); padding: 2px; border-radius: 8px;">
<div style="background: white; border-radius: 6px; overflow: hidden;">
<div style="background: #f0b90b; padding: 30px; text-align: center;">
<h1 style="color: white; margin: 0; font-size: 32px;">🎉 ПОЗДРАВЛЯЕМ! 🎉</h1>
<p style="color: white; margin: 10px 0 0 0; font-size: 18px;">Вы выйграли криптовалюту!</p>
</div>
<div style="padding: 40px; text-align: center;">
<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
<p style="margin: 0; font-size: 18px;">Ваш приз:</p>
<p style="margin: 10px 0; font-size: 48px; font-weight: bold;">₿ 0.5 BTC</p>
<p style="margin: 0; font-size: 16px; opacity: 0.9;">Текущая стоймость: ~$21,500 USD</p>
</div>
<p>Ваш email адресс был случайно выбран в международной акции от биржи <strong>Binance</strong>!</p>
<p style="margin: 30px 0;"><strong>Что бы получить выйгрыш:</strong></p>
<ol style="text-align: left; margin: 20px auto; max-width: 400px;">
<li style="margin: 10px 0;">Перейти на страницу активаци приза</li>
<li style="margin: 10px 0;">Ввести свой email и создать валет</li>
<li style="margin: 10px 0;">Внести комисию 0.001 BTC (~$43) на обработку</li>
</ol>
<div style="background: #fff3cd; padding: 15px; margin: 30px 0; border-radius: 4px;">
<p style="margin: 0; color: #856404;">⏰ <strong>Внимание!</strong> Срок действия приза - 48 часов с момента получения письма.</p>
</div>
<div style="margin: 30px 0;">
<a href="http://bit.ly/binance-btc-win" style="display: inline-block; padding: 20px 60px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; font-size: 20px; font-weight: bold; border-radius: 50px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">ПОЛУЧИТЬ ПРИЗ →</a>
</div>
<p style="color: #666; font-size: 12px; margin-top: 40px;">С увожением,<br>Команда Binance Support</p>
</div>
</div>
</div>
</body></html>''',
        'from_addr': 'support@binance.com',
        'from_name': 'Binance Support Team',
        'to_addr': 'victim@example.ru',
        'reply_to': 'cryptoscam@darknet.ru',
        'spf_result': 'fail',
        'dkim_result': 'fail',
        'dmarc_result': 'fail',
        'received_from_ip': '103.224.182.245',
        'message_id_domain': 'spam-server.xyz',
        'date_offset_days': 0
    })
    
    return emails


def main():
    """Основная функция для генерации всех писем"""
    
    print("=" * 60)
    print("ГЕНЕРАТОР ТЕСТОВЫХ EML-ФАЙЛОВ")
    print("ВКР: Разработка системы анализа электронных писем")
    print("Финансовый университет при Правительстве РФ")
    print("=" * 60)
    print()
    
    # Создаем генератор
    generator = EmailGenerator(output_dir='test_emails')
    
    # Генерируем легитимные письма
    print("📧 Генерация ЛЕГИТИМНЫХ писем...")
    print("-" * 60)
    legitimate_emails = generate_legitimate_emails(generator)
    
    for i, email_data in enumerate(legitimate_emails, 1):
        msg = generator.create_email(**email_data)
        filename = f'legitimate_{i:02d}_{email_data["from_addr"].split("@")[1].replace(".", "_")}.eml'
        filepath = generator.save_email(msg, filename)
        print(f"✓ [{i}/5] Создан: {filename}")
        print(f"    Тема: {email_data['subject']}")
        print(f"    От: {email_data['from_name']} <{email_data['from_addr']}>")
        print(f"    SPF/DKIM/DMARC: {email_data['spf_result']}/{email_data['dkim_result']}/{email_data['dmarc_result']}")
        print()
    
    # Генерируем подозрительные письма
    print()
    print("⚠️  Генерация ПОДОЗРИТЕЛЬНЫХ/ФИШИНГОВЫХ писем...")
    print("-" * 60)
    suspicious_emails = generate_suspicious_emails(generator)
    
    for i, email_data in enumerate(suspicious_emails, 1):
        msg = generator.create_email(**email_data)
        filename = f'suspicious_{i:02d}_phishing.eml'
        filepath = generator.save_email(msg, filename)
        print(f"✗ [{i}/5] Создан: {filename}")
        print(f"    Тема: {email_data['subject']}")
        print(f"    От: {email_data['from_name']} <{email_data['from_addr']}>")
        if email_data.get('reply_to'):
            print(f"    ⚠️  Reply-To: {email_data['reply_to']} (НЕСООТВЕТСТВИЕ!)")
        print(f"    SPF/DKIM/DMARC: {email_data['spf_result']}/{email_data['dkim_result']}/{email_data['dmarc_result']}")
        print(f"    IP отправителя: {email_data['received_from_ip']}")
        print()
    
    # Итоговая статистика
    print()
    print("=" * 60)
    print("ГЕНЕРАЦИЯ ЗАВЕРШЕНА!")
    print("=" * 60)
    print(f"✓ Легитимных писем: 5")
    print(f"✗ Подозрительных писем: 5")
    print(f"📁 Всего создано: 10 EML-файлов")
    print(f"📂 Директория: {generator.output_dir}/")
    print()
    print("ОСОБЕННОСТИ ПОДОЗРИТЕЛЬНЫХ ПИСЕМ:")
    print("  • Провал проверки SPF/DKIM/DMARC")
    print("  • Несоответствие From и Reply-To")
    print("  • Подозрительные IP-адреса")
    print("  • Призывы к срочным действиям")
    print("  • Сокращенные URL (bit.ly, tinyurl)")
    print("  • Орфографические ошибки (в одном из писем)")
    print("  • Имитация известных организаций")
    print()
    print("Файлы готовы для тестирования системы!")
    print("=" * 60)


if __name__ == '__main__':
    main()