-- Migration 0004: High-Fidelity PDF & HTML Storage and Extended Feeds

alter table reports add column if not exists raw_html text not null default '';
alter table reports add column if not exists pdf_url text not null default '';
alter table reports add column if not exists pdf_base64 text not null default '';

-- Add RSS feed URL to sources if not exists
alter table sources add column if not exists feed_url text not null default '';

-- Seed common CTI RSS feeds
update sources set feed_url = 'https://thedfirreport.com/feed/' where slug = 'dfir';
update sources set feed_url = 'https://unit42.paloaltonetworks.com/feed/' where slug = 'unit42';
update sources set feed_url = 'https://www.sentinelone.com/labs/feed/' where slug = 'sentinellabs';
update sources set feed_url = 'https://www.cisa.gov/cybersecurity-advisories.xml' where slug = 'cisa';
update sources set feed_url = 'https://blog.talosintelligence.com/feeds/posts/default' where slug = 'talos';
update sources set feed_url = 'https://cloud.google.com/feeds/threat-intelligence.xml' where slug = 'mandiant';
update sources set feed_url = 'https://www.huntress.com/blog/rss.xml' where slug = 'huntress';
update sources set feed_url = 'https://www.elastic.co/security-labs/rss/feed.xml' where slug = 'elastic';
