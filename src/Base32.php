<?php

namespace PedroSancao;

class Base32
{

    public static function encode($data, $padding = true)
    {
        $binary = $encoded = '';
        $map = array_merge(range('A', 'Z'), range(2, 7));
        $chars = str_split($data);
        $charsLimit = count($chars);
        for ($i = 0; $i < $charsLimit; $i++) {
            $binary .= str_pad(decbin(ord($chars[$i])), 8, 0, STR_PAD_LEFT);
        }
        $groups = str_split($binary, 5);
        $groupsLimit = count($groups) - 1;
        for ($i = 0; $i < $groupsLimit; $i++) {
            $encoded .= $map[bindec($groups[$i])];
        }
        $encoded .= $map[bindec(str_pad($groups[$groupsLimit], 5, 0))];
        $encoded .= $padding ? str_repeat('=', 7 - (strlen($encoded) - 1) % 8) : '';
        return $encoded;
    }

    public static function decode($data)
    {
        $binary = $decoded = '';
        $replacements = array(
            '0' => 'O',
            '1' => 'I',
            ' ' => '',
        );
        $map = array_flip(array_merge(range('A', 'Z'), range(2, 7)));
        $normalized = strtr(strtoupper(rtrim($data, '=')), $replacements);
        if (preg_match('/[^A-Z2-7]/', $normalized)) {
            return false;
        }
        $chars = str_split($normalized);
        $charsCount = count($chars);
        for ($i = 0; $i < $charsCount; $i++) {
            $binary .= str_pad(decbin($map[$chars[$i]]), 5, 0, STR_PAD_LEFT);
        }
        $groups = str_split(substr($binary, 0, strlen($binary) - strlen($binary) % 8), 8);
        $groupsLimit = count($groups);
        for ($i = 0; $i < $groupsLimit; $i++) {
            $decoded .= chr(bindec($groups[$i]));
        }
        return $decoded;
    }

}
