If you don't like a dua stored in the database, you'll need to execute a number of deletes

For example, if you want to delete any ast with a name like '%parameter%' (% is wildcard) before line 2929, you should run the following


delete from bug where trigger in (select id from duabytes where dua in (select id from dua where lval in (select id from sourcelval where ast_name like '%parameter%' and loc_begin_line<2929)));
delete from duabytes where dua in (select id from dua where lval in (select id from sourcelval where ast_name like '%parameter%' and loc_begin_line<2929));
delete from dua where lval in (select id from sourcelval where ast_name like '%parameter%' and loc_begin_line<2929);
delete from sourcelval where ast_name like '%parameter%' and loc_begin_line<2929;

You may get errors about the built_bugs table and the run table, if you've already built targets containing those bad duas. You can just delete everything in those tables.
