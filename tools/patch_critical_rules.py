"""Apply Russian recommendations to the top critical PingCastle rules.

Edits the in-place catalog file. Idempotent: if a rule already has Russian
text (title не начинается с "PingCastle "), it is left untouched. Run once
to upgrade stubs to fully written entries.
"""
from __future__ import annotations

from pathlib import Path

import yaml

CATALOG = Path(__file__).resolve().parents[1] / "src" / "adreport" / "catalog" / "recommendations.yaml"


# RiskId → fields to set. recommendation is multi-line literal.
PATCHES: dict[str, dict] = {
    # =================================================== критичность 100
    "S-Vuln-MS14-068": {
        "title": "Контроллеры домена уязвимы к MS14-068 (Kerberos PAC)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "уязвимых контроллеров домена",
        "recommendation": (
            "Срочно установить обновление безопасности MS14-068 (KB3011780) на все контроллеры "
            "домена. Без патча любой аутентифицированный пользователь может подделать PAC и "
            "получить права администратора домена.\n\n"
            "До установки патча — изолировать DC, мониторить event 4769 с подозрительными ticket "
            "options. Проверить наличие индикаторов компрометации (Mimikatz Kerberos::pac)."
        ),
    },
    "S-Vuln-MS17_010": {
        "title": "Системы уязвимы к MS17-010 (EternalBlue / SMBv1 RCE)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "уязвимых хостов",
        "recommendation": (
            "Срочно установить обновление безопасности MS17-010 (KB4013389 и связанные) на все "
            "затронутые хосты. Уязвимость в SMBv1 позволяет удалённое выполнение кода без "
            "аутентификации (EternalBlue) — лежала в основе WannaCry / NotPetya.\n\n"
            "Дополнительно: полностью отключить SMBv1 (Disable-WindowsOptionalFeature -Online "
            "-FeatureName SMB1Protocol). На современных Windows SMBv1 не требуется."
        ),
    },
    "T-SIDFiltering": {
        "title": "На исходящем доверии отключена фильтрация SID History",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "доверий без фильтрации SID",
        "recommendation": (
            "Включить SID Filtering на исходящих доверительных отношениях леса:\n"
            "  netdom trust <trusted_domain> /domain:<our_domain> /quarantine:yes\n\n"
            "Без фильтрации атакующий в доверенном лесу может добавить SID администраторов "
            "нашего леса в SID History своей УЗ и получить домен-админ привилегии у нас (классическая "
            "SID History injection)."
        ),
    },

    # =================================================== 60
    "S-OS-NT": {
        "title": "Использование Windows NT (вне поддержки с 2004 года)",
        "type": "Уязвимость",
        "segment": "Пользовательский",
        "count_label": "хостов с Windows NT",
        "recommendation": (
            "Немедленно вывести из эксплуатации все системы под управлением Windows NT 4.0. "
            "ОС не получает security-обновлений более 20 лет, уязвима практически ко всему — "
            "от MS06-040 до MS17-010. Если есть промышленные системы — вынести в полностью "
            "изолированный сегмент без сетевого доступа."
        ),
    },

    # =================================================== 50
    "A-Krbtgt": {
        "title": "Пароль учётной записи krbtgt не менялся более года",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "(пароль krbtgt не ротирован)",
        "recommendation": (
            "Произвести двукратную смену пароля krbtgt с интервалом >10 часов "
            "(скрипт Microsoft Reset-KrbTgt-Password.ps1).\n\n"
            "Без ротации, если атакующий когда-либо получал NT-хеш krbtgt (через DCSync, "
            "компрометацию DC), он сохраняет возможность создавать Golden Ticket для любого "
            "пользователя домена. Рекомендуемая частота — каждые 6-12 месяцев и обязательно "
            "после любого подозрения на компрометацию tier-0."
        ),
    },
    "T-SIDHistorySameDomain": {
        "title": "Учётные записи имеют SIDHistory из того же домена",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "УЗ с подозрительным SIDHistory",
        "recommendation": (
            "Расследовать УЗ с SIDHistory того же домена — это нештатное состояние, "
            "характерное для атаки SID History injection (Mimikatz dcshadow, Impacket).\n\n"
            "Очистить атрибут sIDHistory у легитимных УЗ через ADSI Edit или Set-ADUser "
            "-Remove. Включить аудит изменений SIDHistory (Event 4765/4766)."
        ),
    },

    # =================================================== 40
    "S-DC-2000": {
        "title": "Контроллеры домена под управлением Windows 2000",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "DC на Windows 2000",
        "recommendation": (
            "Срочно вывести из эксплуатации контроллеры домена под управлением Windows 2000 "
            "Server. ОС не получает обновлений безопасности с 2010 года. Перенести роли FSMO "
            "на современные DC (Windows Server 2019/2022), затем dcpromo /demote на старых.\n\n"
            "Наличие DC на Windows 2000 блокирует повышение functional level и оставляет домен "
            "уязвимым к множеству атак (ms-DS-Behavior-Version='0')."
        ),
    },
    "S-OS-2000": {
        "title": "Использование Windows 2000 на рабочих станциях / серверах",
        "type": "Уязвимость",
        "segment": "Пользовательский",
        "count_label": "хостов с Windows 2000",
        "recommendation": (
            "Немедленно вывести из эксплуатации все Windows 2000 системы. ОС не получает "
            "обновлений безопасности с 2010 года и уязвима к десяткам критических CVE без патчей."
        ),
    },

    # =================================================== 30
    "A-SmartCardRequired": {
        "title": "Привилегированная УЗ с SmartCardRequired имеет статический NT-хеш",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "УЗ со статическим хешем",
        "recommendation": (
            "При установленном флаге «Smart card is required for interactive logon» Windows "
            "генерирует случайный пароль один раз и не ротирует его. Если хеш такой УЗ "
            "когда-либо был скомпрометирован (DCSync), он остаётся валидным навсегда.\n\n"
            "Раз в 6 месяцев снимать и снова устанавливать флаг SmartCardRequired — это форсит "
            "генерацию нового пароля и инвалидирует старые хеши."
        ),
    },
    "P-Inactive": {
        "title": "Привилегированная учётная запись неактивна более 6 месяцев",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "неактивных привилегированных УЗ",
        "recommendation": (
            "Отключить или удалить привилегированные учётные записи, не использовавшиеся более "
            "6 месяцев. Активные неиспользуемые tier-0 УЗ — типичная мишень credential stuffing "
            "и password spraying; их компрометация даёт мгновенный доступ к домену."
        ),
    },
    "S-C-Inactive": {
        "title": "Неактивные компьютеры в Active Directory",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "неактивных компьютеров",
        "recommendation": (
            "Отключить или удалить из AD computer-объекты, не подключавшиеся к домену более "
            "180 дней. Неактивные хосты — потенциальный путь для атак (старые ОС без патчей, "
            "слабые пароли локального админа, отсутствие современного антивируса). "
            "Использовать Search-ADAccount -AccountInactive -TimeSpan 180.00:00:00."
        ),
    },
    "S-OS-2003": {
        "title": "Использование Windows Server 2003 (вне поддержки с 2015 года)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "серверов Windows Server 2003",
        "recommendation": (
            "Срочно вывести из эксплуатации или мигрировать серверы Windows Server 2003/2003 R2 "
            "на актуальные версии (Windows Server 2019/2022). Расширенная поддержка завершилась "
            "14.07.2015, security-обновления не выпускаются. До миграции изолировать в отдельный "
            "VLAN с минимальным сетевым доступом."
        ),
    },

    # =================================================== 25
    "P-ControlPathIndirectEveryone": {
        "title": "Группа Everyone имеет непрямой control path до привилегированных объектов",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "control path к привилегиям",
        "recommendation": (
            "Провести аудит ACL объектов AD: найти и устранить цепочки прав, ведущие от "
            "псевдогруппы Everyone к привилегированным объектам (Domain Admins, Schema Admins, "
            "контроллеры домена). Использовать BloodHound для построения графа путей атаки.\n\n"
            "Удалить избыточные ACE с Everyone / Authenticated Users / Domain Users на "
            "tier-0 объектах."
        ),
    },
    "P-ControlPathIndirectMany": {
        "title": "Большое число УЗ имеет непрямой control path до привилегий",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "УЗ с control path к привилегиям",
        "recommendation": (
            "Провести аудит непрямых путей повышения привилегий через цепочки ACL "
            "(WriteOwner → ResetPassword, GenericAll → AddSelf-to-group, и т.п.). "
            "Использовать BloodHound (Cypher-запросы) для выявления коротких путей "
            "от непривилегированных УЗ до Domain Admins.\n\n"
            "Применить tiered admin model: разделить tier-0/1/2 учётные записи, "
            "запретить кросс-тиер logon."
        ),
    },

    # =================================================== ADCS family
    "A-CertROCA": {
        "title": "ADCS: используются сертификаты, уязвимые к ROCA (CVE-2017-15361)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "ROCA-уязвимых сертификатов",
        "recommendation": (
            "Перевыпустить все сертификаты, сгенерированные на уязвимом криптопроцессоре Infineon "
            "TPM (RSALib до 1.02.013). ROCA позволяет восстановить приватный ключ за разумное "
            "время даже для 2048-битных ключей. Использовать ROCA detection tool для проверки.\n\n"
            "Запретить выпуск новых сертификатов с проблемными RSA-ключами через политику CA."
        ),
    },
    "A-CertTempAnyone": {
        "title": "ADCS: шаблон сертификата доступен Authenticated Users / Domain Users",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "опасных шаблонов сертификатов",
        "recommendation": (
            "Ограничить право Enroll на шаблонах сертификатов конкретными группами (не "
            "Authenticated Users / Domain Users). Если шаблон содержит EKU «Client Authentication» "
            "или «Smart Card Logon» и доступен всем — это путь к импersonation любого пользователя "
            "(ESC1/ESC2/ESC3).\n\n"
            "Проверить msPKI-Certificate-Name-Flag (ENROLLEE_SUPPLIES_SUBJECT) — должен быть 0 "
            "для пользователе-доступных шаблонов."
        ),
    },
    "A-CertTempAgent": {
        "title": "ADCS: шаблон сертификата с EKU «Certificate Request Agent» (ESC3)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "шаблонов с Enrollment Agent",
        "recommendation": (
            "Удалить EKU «Certificate Request Agent» (1.3.6.1.4.1.311.20.2.1) с шаблонов "
            "сертификатов, доступных рядовым пользователям. Этот EKU позволяет владельцу "
            "выпускать сертификаты от имени других пользователей (ESC3-атака в Certified "
            "Pre-Owned).\n\n"
            "Если EKU необходим — ограничить список enrollment agents и subjects через "
            "Certificate Manager Restrictions."
        ),
    },
    "A-CertTempAnyPurpose": {
        "title": "ADCS: шаблон сертификата с EKU «Any Purpose» / без EKU (ESC2)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "опасных шаблонов сертификатов",
        "recommendation": (
            "Удалить EKU «Any Purpose» (2.5.29.37.0) или «Subordinate Certification Authority» "
            "со всех шаблонов, доступных не-CA пользователям. Эти EKU позволяют использовать "
            "сертификат как промежуточный CA для подписи произвольных сертификатов (ESC2)."
        ),
    },
    "A-CertTempCustomSubject": {
        "title": "ADCS: шаблон сертификата позволяет указывать произвольный Subject (ESC1)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "ESC1-уязвимых шаблонов",
        "recommendation": (
            "Снять флаг msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT (бит 1) у шаблонов "
            "с EKU Client Authentication. ESC1 позволяет любому пользователю с правом Enroll "
            "получить сертификат с произвольным UPN в Subject — то есть аутентифицироваться "
            "от имени любого пользователя домена, включая администратора.\n\n"
            "Либо использовать pkinit_freshness_extension (Windows Server 2022)."
        ),
    },
    "A-CertTempNoSecurity": {
        "title": "ADCS: шаблон сертификата выпускается без согласования (No Approval)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "шаблонов без апрува",
        "recommendation": (
            "Включить «CA certificate manager approval» на шаблонах с критичными EKU "
            "(Client Authentication, Smart Card Logon). Это требует ручной валидации каждого "
            "запроса администратором CA и не даёт автоматически выпускать сертификаты "
            "по уязвимым шаблонам."
        ),
    },
    "A-DC-Coerce": {
        "title": "Контроллеры домена уязвимы к атакам coercion (PetitPotam / DFSCoerce)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "уязвимых контроллеров домена",
        "recommendation": (
            "Применить митигации против coercion-атак на DC:\n"
            "  • установить KB5005413 + настроить параметры реестра против PetitPotam (EFSRPC);\n"
            "  • установить обновления для DFSCoerce и PrinterBug (Print Spooler);\n"
            "  • включить EPA (Extended Protection for Authentication) на LDAPS и AD CS Web;\n"
            "  • заблокировать NTLM relay в AD CS (включить «Force HTTPS», EPA, отключить HTTP).\n\n"
            "Без митигаций атакующий принуждает DC аутентифицироваться к ADCS, релеит NTLM и "
            "получает сертификат DC → KRBTGT → Golden Ticket."
        ),
    },
    "A-DC-Spooler": {
        "title": "На контроллерах домена включён Print Spooler (PrinterBug)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "DC с включённым Print Spooler",
        "recommendation": (
            "Отключить службу Print Spooler на всех контроллерах домена:\n"
            "  Stop-Service Spooler; Set-Service Spooler -StartupType Disabled\n\n"
            "Print Spooler на DC уязвим к атаке PrinterBug (MS-RPRN) — атакующий принуждает DC "
            "аутентифицироваться к произвольному хосту, что используется для coercion → relay "
            "(см. SpoolSample, dementor.py)."
        ),
    },

    # =================================================== SMB / NTLM / Pwd
    "S-SMB-v1": {
        "title": "На контроллерах домена включён SMBv1",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "DC с SMBv1",
        "recommendation": (
            "Отключить SMBv1 на всех DC и серверах:\n"
            "  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n\n"
            "SMBv1 уязвим к EternalBlue (MS17-010), не поддерживает signing/encryption, является "
            "точкой входа для ransomware (WannaCry, NotPetya). На современных Windows SMBv1 "
            "не нужен (поддержка только для древних NAS/принтеров)."
        ),
    },
    "S-OldNtlm": {
        "title": "Разрешена аутентификация LM / NTLMv1",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "хостов с разрешённым NTLMv1/LM",
        "recommendation": (
            "Установить «Network security: LAN Manager authentication level» = «Send NTLMv2 "
            "response only. Refuse LM & NTLM» (уровень 5) через доменную GPO. LM-хеши тривиально "
            "крекаются (rainbow tables), NTLMv1 уязвим к downgrade и relay-атакам. NTLMv2 "
            "обязателен; SMB signing / LDAP signing обязательны."
        ),
    },
    "S-PwdNotRequired": {
        "title": "Учётные записи с флагом PASSWD_NOTREQD",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "УЗ с PASSWD_NOTREQD",
        "recommendation": (
            "Снять флаг PASSWD_NOTREQD (бит 0x00000020 в userAccountControl) со всех УЗ. "
            "Аккаунты без требования пароля могут иметь пустой пароль — мгновенный logon без "
            "credential. Команда:\n"
            "  Get-ADUser -Filter 'UserAccountControl -band 0x20' | "
            "Set-ADUser -PasswordNotRequired $false"
        ),
    },
    "A-NullSession": {
        "title": "Контроллеры домена принимают анонимные SMB-сессии (null session)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "DC с null session",
        "recommendation": (
            "Отключить null session на DC через политику «Network access: Restrict anonymous "
            "access to Named Pipes and Shares» и удалить любые pipes/shares из «Network access: "
            "Named Pipes that can be accessed anonymously».\n\n"
            "Null session позволяет анонимно перечислять пользователей, группы, share — это "
            "первый шаг во многих pre-auth атаках."
        ),
    },
    "A-LAPS-Not-Installed": {
        "title": "Не развёрнут LAPS / Windows LAPS",
        "type": "Уязвимость",
        "segment": "Пользовательский",
        "count_label": "хостов без LAPS",
        "recommendation": (
            "Развернуть Windows LAPS (встроен в Windows Server 2019+) или legacy Microsoft LAPS "
            "на все workstation и member server. Без LAPS пароль локального администратора "
            "одинаков на множестве хостов; компрометация одного → доступ ко всем (классический "
            "lateral movement / pass-the-hash)."
        ),
    },

    # =================================================== P-family
    "P-AdminLogin": {
        "title": "Пароль учётной записи Administrator не менялся длительное время",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "(пароль built-in Administrator не ротирован)",
        "recommendation": (
            "Сменить пароль встроенной УЗ Administrator (RID 500). Установить процедуру ротации "
            "не реже одного раза в 6 месяцев. Эта УЗ — главная мишень атак (нельзя "
            "lock out, всегда существует), её хеш используется в pass-the-hash, скомпрометированный "
            "пароль действителен всегда."
        ),
    },
    "P-Delegated": {
        "title": "Пользователям делегированы избыточные права над OU / привилегированными объектами",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "избыточных делегирований",
        "recommendation": (
            "Провести аудит делегированных прав (Delegation of Control) на OU и tier-0 объекты. "
            "Удалить ACE для непривилегированных пользователей. Использовать BloodHound для "
            "визуализации непрямых путей повышения привилегий через делегированные права."
        ),
    },
    "P-DCOwner": {
        "title": "Нестандартный владелец (Owner) объекта контроллера домена",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "DC с нестандартным владельцем",
        "recommendation": (
            "Восстановить владельца computer-объектов DC в Domain Admins / Enterprise Admins. "
            "Владелец имеет неявное право WriteDACL — может выдать себе любые права на DC "
            "(включая delegation, что ведёт к domain takeover)."
        ),
    },
    "P-ServiceDomainAdmin": {
        "title": "Сервисные учётные записи входят в Domain Admins / Enterprise Admins",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "сервисных УЗ в DA",
        "recommendation": (
            "Удалить сервисные учётные записи из Domain Admins / Enterprise Admins. Заменить "
            "на gMSA (Group Managed Service Accounts) с минимальными правами. Сервисные УЗ с "
            "правами DA — главная мишень Kerberoasting (длинный неротируемый пароль + "
            "извлечение TGS-REP хеша)."
        ),
    },
    "P-RecoveryModeUnprotected": {
        "title": "Пароль Directory Services Restore Mode (DSRM) не защищён",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "DC с незащищённым DSRM",
        "recommendation": (
            "Включить синхронизацию DSRM-пароля с доменной УЗ (DsrmAdminLogonBehavior = 0) "
            "и регулярно её ротировать. DSRM — локальный admin-пароль DC, используется для "
            "восстановления AD. Если он скомпрометирован, атакующий может загрузить DC в "
            "Directory Services Restore Mode и манипулировать ntds.dit."
        ),
    },

    # =================================================== misc 15-pt
    "A-MembershipEveryone": {
        "title": "Группа содержит Everyone / Authenticated Users в составе",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "групп с Everyone в составе",
        "recommendation": (
            "Удалить псевдогруппы Everyone, Authenticated Users, Domain Users из явного состава "
            "доменных групп (особенно привилегированных). Эти токены добавляются автоматически "
            "при logon — явное включение в группу часто является следствием некорректного "
            "восстановления или атаки."
        ),
    },
    "P-DelegationGPOData": {
        "title": "Делегированы права на запись в GPO непривилегированным УЗ",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "GPO с делегированной записью",
        "recommendation": (
            "Удалить право Write на GPO у непривилегированных пользователей. GPO применяются "
            "на DC и member-серверах с правами SYSTEM — модификация GPO непривилегированной УЗ "
            "ведёт к выполнению произвольного кода на всех хостах в области действия (атака "
            "SharpGPOAbuse)."
        ),
    },
    "P-DelegationLoginScript": {
        "title": "Делегированы права на запись Logon Script",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "logon script с делегированной записью",
        "recommendation": (
            "Удалить право Write на скрипты входа (Logon/Logoff/Startup) у непривилегированных "
            "УЗ. Скрипты исполняются на каждом logon — подмена скрипта даёт RCE на всех "
            "пользователях / компьютерах в области действия."
        ),
    },
    "P-UnkownDelegation": {
        "title": "Обнаружены неизвестные / нештатные делегирования",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "неизвестных делегирований",
        "recommendation": (
            "Расследовать каждое нештатное делегирование. Любое непрозрачное право Modify "
            "Permission / Take Ownership / Write Owner на объекты AD — потенциальный путь "
            "повышения привилегий. Использовать AD ACL Scanner / BloodHound."
        ),
    },
    "A-ReversiblePwd": {
        "title": "Учётные записи с обратимым шифрованием пароля",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "УЗ с обратимым шифрованием",
        "recommendation": (
            "Снять флаг ENCRYPTED_TEXT_PASSWORD_ALLOWED (бит 0x80 в userAccountControl) у всех "
            "пользователей. С этим флагом Windows хранит пароль в виде, обратимом до plaintext, "
            "и атакующий может извлечь его через DCSync (Mimikatz lsadump::dcsync)."
        ),
    },
    "P-ExchangePrivEsc": {
        "title": "Exchange имеет избыточные права над AD (CVE-2019-0686 / Privilege Escalation)",
        "type": "Уязвимость",
        "segment": "Серверный",
        "count_label": "избыточных прав Exchange",
        "recommendation": (
            "Применить Microsoft Active Directory Split Permissions Model или ноябрьский security "
            "update 2019 года. Группы Exchange (Exchange Trusted Subsystem, Exchange Windows "
            "Permissions) имели права WriteDACL на корень домена — это позволяло атакующему с "
            "правами обычного Mailbox-пользователя получить DA через PrivExchange."
        ),
    },
}


def main() -> int:
    with CATALOG.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    recs = data["recommendations"]
    patched = 0
    missing = []
    for risk_id, patch in PATCHES.items():
        if risk_id not in recs:
            missing.append(risk_id)
            continue
        recs[risk_id].update(patch)
        patched += 1

    # Re-dump preserving the file header (the original comment block).
    header = CATALOG.read_text(encoding="utf-8").split("\nrecommendations:", 1)[0]

    def _str_repr(dumper, value):
        if "\n" in value:
            return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", value)

    yaml.add_representer(str, _str_repr)

    body = yaml.dump(data, allow_unicode=True, sort_keys=False, width=10000)
    CATALOG.write_text(header + "\n" + body, encoding="utf-8")
    print(f"Patched: {patched} rules")
    if missing:
        print(f"WARN: {len(missing)} RiskIds were absent from catalog (typo?): {missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
