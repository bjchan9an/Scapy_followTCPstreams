def color_print(color,data,choice=''):
    color_board={'RED_BACK'   :'41m',
                 'GREEN_BACK' :'42m',
                 'BLUE_BACK'  :'44m',
                 'PUPLE_BACK' :'45m',
                 'SEA_BACK'   :'46m',
                 
                 'RED_WORD'   :'31m',
                 'GREEN_WORD' :'32m',
                 'BLUE_WORD'  :'34m',
                 'PUPLE_BACK' :'35m',
                 'SEA_WORD'   :'36m'}
    return '\033['+choice+color_board[color]+data+'\033[0m'
