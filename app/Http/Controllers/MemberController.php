<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

use Laravel\Lumen\Routing\Controller as BaseController;

class MemberController extends BaseController
{
    public function register(Request $request) {

        //Retrive data from post
        $email = $request->input('email');
        $password = $request->input('password');
        $name = $request->input('name');

        //Verify data
        if($email === null || $password === null || $name === null) {
            return response()->json(['code' => 100, 'message' => 'Data blank detected.']);
        }
        if(strlen($email) > 128 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['code' => 101, 'message' => 'Email format illegal.']);
        }
        if(!preg_match('/^[\w\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\>\=\?\@\[\]\{\}\\\\\\\\\^\`\~]{8,1024}$/', $password)) {
            return response()->json(['code' => 102, 'message' => 'Password format illegal.']);
        }
        if(strlen($name) > 128) {
            return response()->json(['code' => 103, 'message' => 'Name format illegal.']);
        }

        //Processing with Database

        //Check email existing
        try {
            $email_existing = DB::table('member')->where('member_email', $email)->value('member_email');
            if($email_existing === $email) {
                return response()->json(['code' => 104, 'message' => 'Email existing.']);
            }
        }catch (Exception $e) {
            return response()->json(['code' => 500, 'message' => $e]);
        }

        //Write member data into database
        try {
            $password = hash('sha3-256', $password);
            $member_inserted = DB::insert('insert into member (member_email, member_password, member_name) values (?, ?, ?)', [$email, $password, $name]);
            if($member_inserted) {
                return response()->json(['code' => 200, 'message' => 'Success.']);
            }else {
                return response()->json(['code' => 500, 'message' => 'Internal Server Error.']);
            }
        }catch (Exception $e) {
            return response()->json(['code' => 500, 'message' => $e]);
        }

        return response()->json(['code' => 500, 'message' => 'Internal Server Error.']);

    }

    public function login(Request $request) {

        //Retrive data from post
        $email = $request->input('email');
        $password = $request->input('password');

        //Verify data
        if($email === null || $password === null) {
            return response()->json(['code' => 100, 'message' => 'Data blank detected.']);
        }
        if(strlen($email) > 128 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['code' => 101, 'message' => 'Email format illegal.']);
        }
        if(!preg_match('/^[\w\!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\>\=\?\@\[\]\{\}\\\\\\\\\^\`\~]{8,1024}$/', $password)) {
            return response()->json(['code' => 102, 'message' => 'Password format illegal.']);
        }

        //Check member authentication info
        try {
            $password = hash('sha3-256', $password);
            $member_unique_id = DB::table('member')->where('member_email', $email)->where('member_password', $password)->value('member_unique_id');
            if($member_unique_id === null) {
                return response()->json(['code' => 103, 'message' => 'Member not existing or wrong password.']);
            }
        }catch (Exception $e) {
            return response()->json(['code' => 500, 'message' => $e]);
        }

        //Insert a new token
        try {
            $token = '1234';
            $token_inserted = DB::insert('insert into login_token (login_unique_id, login_token, login_timestamp) values (?, ?, now())', [$member_unique_id, $token]);
            if($token_inserted) {
                return response()->json(['code' => 200, 'message' => 'Success.']);
            }else {
                return response()->json(['code' => 500, 'message' => 'Internal Server Error.']);
            }
        }catch (Exception $e) {
            return response()->json(['code' => 500, 'message' => $e]);
        }
    }
}
