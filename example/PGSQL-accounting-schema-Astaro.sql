-- Table definitions for the accounting subsystem
--
-- cmoench@astaro.com 

create table accounting (
	srcip				inet,
	dstip				inet,
	ip_protocol			integer,
	l4_dport			integer,
	raw_in_pktlen		bigint,
	raw_in_pktcount		bigint,
	raw_out_pktlen		bigint,
	raw_out_pktcount	bigint,
	logday				date,
	flow_duration		integer,
	flow_count			bigint default 1,
	_rowno				bigserial,
	primary key			(_rowno)
);

create index accounting_dayidx on accounting (
	logday
);

create index accounting_idx on accounting (
	logday, srcip, dstip, ip_protocol, l4_dport
);

create or replace function ins_accounting(
	saddr inet, saddr6 inet, daddr inet, daddr6 inet,
	proto integer, port integer,
	in_len bigint, in_cnt bigint, out_len bigint, out_cnt bigint,
	flow_start integer, duration integer
) returns void as $$
declare
	day		date;
	src		inet;
	dst		inet;
begin
	day = date 'epoch' + flow_start * interval '1 second';
	src = coalesce(saddr, saddr6);
	dst = coalesce(daddr, daddr6);

	update accounting set
		raw_in_pktlen = raw_in_pktlen + in_len,
		raw_in_pktcount = raw_in_pktcount + in_cnt,
		raw_out_pktlen = raw_out_pktlen + out_len,
		raw_out_pktcount = raw_out_pktcount + out_cnt,
		flow_count = flow_count + 1
	where
		logday = day and
		srcip = src and
		dstip = dst and
		ip_protocol = proto and
		l4_dport = port;

	if not found then
		insert into accounting (
			srcip, dstip, ip_protocol, l4_dport,
			raw_in_pktlen, raw_in_pktcount, raw_out_pktlen, raw_out_pktcount,
			logday, flow_duration, flow_count
		) values (
			src, dst, proto, port, in_len, in_cnt, out_len, out_cnt,
			day, duration, 1
		);
	end if;
			
end;
$$ language plpgsql;

