def human_readable_eta(seconds):
    days = seconds // 86400
    hours = seconds // 3600 % 24
    minutes = seconds // 60 % 60
    seconds = seconds % 60
    ret = str(round(days)) + "d" if days > 0 else ""
    ret += str(round(hours)) + "h" if hours > 0 else ""
    ret += str(round(minutes)) + "m" if minutes > 0 else ""
    ret += str(round(seconds)) + "s" if seconds > 0 and minutes < 1 else ""
    return ret
