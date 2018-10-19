

#include "scan.h"

/*
** If argc == 1, then ignore the creation of keyval 
*/

void		destroy_keyval(t_keyval *key_value)
{
	t_keyval	*trav;

	if (key_value->next == NULL)
	{
		free(key_value->option);
		free(key_value->param);
		free(key_value);
		return ;
	}
	while (key_value)
	{
		trav = key_value;
		key_value = key_value->next;
		free(trav->option);
		free(trav->param);
		free(trav);
	}
}

t_keyval	*new_keyval_pair(char *key, char *val)
{
	t_keyval	*newkey;

	newkey = (t_keyval *)malloc(sizeof(t_keyval));
	newkey->option = strdup(key);
	newkey->param = strdup(val);
	newkey->next = NULL;
	return (newkey);
}

t_keyval	*add_keyval_pair(t_keyval *new, char *key,
	char *val)
{
	t_keyval	*trav;

	trav = new;
	while (trav->next)
		trav = trav->next;
	trav->next = (t_keyval*)malloc(sizeof(t_keyval));
	trav->next->option = strdup(key);
	trav->next->param = strdup(val);
	trav->next->next = NULL;
	return (trav);
}

t_keyval 	*key_value_pair(t_keyval *keyvalue, char *key,
	char *val)
{
	t_keyval	*trav;

	trav = keyvalue;
	if (trav == NULL)
	{
		keyvalue = new_keyval_pair(key, val);
		trav = keyvalue;
	}
	else
	{
		trav = add_keyval_pair(keyvalue, key, val);
		trav = keyvalue;
	}
	return (trav);
}




