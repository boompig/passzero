from six import StringIO


def db_export(session, user_id):
    """Export database dump to file.
    Return value of file"""
    if type(user_id) != int and not user_id.isdigit():
        return None
    #TODO this is stupidly unsafe
    sql = "COPY (select * FROM entries WHERE user_id=%s) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)" % user_id
    conn = session.connection().connection
    cur = conn.cursor()
    contents = StringIO.StringIO()
    cur.copy_expert(sql, contents)
    conn.close()
    val = contents.getvalue()
    contents.close()
    return val


