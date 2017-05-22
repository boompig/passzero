from six import StringIO


def db_export(session, user_id):
    """Export database dump to file.
    Return value of file"""
    if type(user_id) != int and not user_id.isdigit():
        raise Exception("User ID must be a digit")
    if type(user_id) != int:
        user_id = int(user_id)
    #TODO string substitution is not the ideal solution here
    # however AFAIK there is no support for this operation in SQLalchemy
    # in order to make this a bit safer force user_id to be int before doing this
    sql = "COPY (select * FROM entries WHERE user_id=%d) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)" % user_id
    conn = session.connection().connection
    assert conn is not None, "Could not get low-level connection object"
    cur = conn.cursor()
    contents = StringIO()
    cur.copy_expert(sql, contents)
    conn.close()
    val = contents.getvalue()
    contents.close()
    return val


