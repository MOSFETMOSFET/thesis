#!/usr/bin/env python

"""Module with dictionary wrapper classes.
This module comes from Nikolaos Kakouros' cheat detection system :
https://kth.diva-portal.org/smash/record.jsf?aq2=%5B%5B%5D%5D&c=29&af=%5B%5D&searchType=LIST_LATEST&sortOrder2=title_sort_asc&query=&language=no&pid=diva2%3A1477521&aq=%5B%5B%5D%5D&sf=all&aqe=%5B%5D&sortOrder=author_sort_asc&onlyFullText=false&noOfRows=50&dswid=-116
"""


# https://stackoverflow.com/questions/2352181

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable


class DotDict(dict):
    """A dict whose keys can be accessed as object properties.
    Example:
    m = DotDict({'first_name': 'Eduardo'}, last_name='Pool', age=24, sports=['Soccer'])
    assert m.first_name == 'Eduardo'
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an dot-traversable dict.
        :param args: dictionaries to convert to DotDict
        :param kwargs: key-value pairs to add to the DotDict
        """
        super().__init__(*args, **kwargs)

        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    if isinstance(v, dict):
                        v = DotDict(v)
                    if isinstance(v, list):
                        v = DotList(*v)

                    self[k] = v

        if kwargs:
            for k, v in kwargs.items():
                if isinstance(v, dict):
                    v = DotDict(v)

                if isinstance(v, list):
                    v = DotList(*v)

                self[k] = v

    def __getitem__(self, key: Any) -> Any:
        """Allow DotDict to behave like a hash.
        :param key: the key to return from the dict
        """
        keys = str(key).split(".")

        if len(keys) == 1:
            return super().__getitem__(key)

        ret = self
        for key in keys:
            ret = ret[key]

        return ret

    def __getattr__(self, attr: str) -> Any:
        """Return dict values using the supplied attribute as key.
        :param attr: the key to return from the dict
        """
        if attr == "__isabstractmethod__":
            # needed for interoperability with ABC, otherwise an object of class
            # that implements and abc will fail when converted to dotdict
            return None

        if attr not in self:
            raise AttributeError(f"dict has no key {attr}")

        return self[attr]

    def __setattr__(self, attr: str, value: Any) -> None:
        """Set a dict entry for the used attribute.
        :param attr: the dict key to set
        :param value: the value to set the key to
        """
        self.__setitem__(attr, value)

    def __setitem__(self, key: str, value: Any) -> None:
        """Allow using the DotDict as a dictionary.
        :param key: the key to set
        :param value: the value to set the key to
        """
        super().__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item: Any) -> None:
        """Allow deleting dict keys using `delattr`.
        :param item: the dict key to remove
        """
        self.__delitem__(item)

    def __delitem__(self, key: str) -> Any:
        """Support deleting keys from the dict.
        :param key: the dict key to delete
        """
        super().__delitem__(key)
        del self.__dict__[key]

    def __deepcopy__(self, memo: dict = None) -> DotDict:
        """Return a copy of the DotDict and of any of its values that are
        objects.
        :param memo: internally required arg
        """
        # https://stackoverflow.com/questions/49901590
        return DotDict(deepcopy(dict(self), memo=memo))

    def __str__(self) -> str:
        """Return a string representation of the DotDict."""
        return dict.__str__(self)

    def __repr__(self) -> str:
        """Return a developer-friendly representation of the DotDict."""
        return dict.__repr__(self)


class DotList(list):
    """A list whose items can be traversed like object atttributes."""

    def __init__(self, *args: Any) -> None:
        """Initialize a dot-traversable list.
        :param args: items to put into the list
        """
        items: Any = []

        for item in args:
            if isinstance(item, dict):
                items.append(DotDict(item))
            elif isinstance(item, list):
                items.append(DotList(*item))
            else:
                items.append(item)

        super().__init__(items)


class DefaultDotDict(DotDict):
    """A DefaultDotDict is to a DotDict what a defaultdict is to a dict."""

    def __init__(self, default_factory: Callable, *args: Any, **kwargs: Any) -> None:
        """Initialize a DefaultDotDict.
        :param default_factory: the Callable to be called when a key is missing
        """
        super(DotDict, self).__init__(*args, **kwargs)
        # Calls the dict init instead of the DotDict init

        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    if isinstance(v, dict):
                        v = DefaultDotDict(default_factory, v)
                    if isinstance(v, list):
                        v = DefaultDotList(default_factory, *v)

                    self[k] = v

        if kwargs:
            for k, v in kwargs.items():
                if isinstance(v, dict):
                    v = DefaultDotDict(default_factory, v)

                if isinstance(v, list):
                    v = DefaultDotList(default_factory, *v)

                self[k] = v

        self.default_factory = default_factory

    def __getattr__(self, attr: str) -> Any:
        """Return the attribute as if it was a key in the dictionary."""
        if attr == "__isabstractmethod__":
            # needed for interoperability with ABC, otherwise an object of class
            # that implements and abc will fail when converted to dotdict
            return None

        return self[attr]

    def __setattr__(self, key: str, value: Any) -> None:
        """Set the attribute as if it was a key in the dictionary.
        If the attribute is default_factory this magic function executes
        with the normal (non-dictionary) behaviour.
        """
        if key == "default_factory":
            self.__dict__.update({key: value})
        else:
            super().__setattr__(key, value)

    def __setitem__(self, key: str, value: Any) -> None:
        """Set the item of key in the dictionary.
        If the key is default_factory this throws an error since the
        Callable should only be changed using the dot-notation.
        """
        if key == "default_factory":
            raise Exception(
                "The Callable 'default_factory' should only be changed using dot-notation."
            )

        super().__setitem__(key, value)

    def __getitem__(self, key: Any) -> Any:
        """Get the item of key in the dictionary.
        If key is default_factory this throws an error since the Callable should only
        be accessed using dot-notation.
        :param key: the key to return from the dict
        """
        if key == "default_factory":
            raise KeyError(
                "The Callable 'default_factory' should only be accessed using dot-notation."
            )

        return super().__getitem__(key)

    def __missing__(self, key: Any) -> Any:
        """Return the factory default value provided by the
        self.default_factory Callable."""
        if self.default_factory is None:
            raise KeyError(f"dict has no key {key} and default_factory is unset.")

        self.__setitem__(key, self.default_factory())
        return self[key]


class DefaultDotList(list):
    """A list that recursively turns dict objects into DefaultDotDict
    objects."""

    def __init__(self, default_factory: Callable, *args: Any) -> None:
        """Recursively turn dict objects into DefaultDotDict objects."""
        items: Any = []

        for item in args:
            if isinstance(item, dict):
                items.append(DefaultDotDict(default_factory, item))
            elif isinstance(item, list):
                items.append(DefaultDotList(default_factory, *item))
            else:
                items.append(item)

        super().__init__(items)