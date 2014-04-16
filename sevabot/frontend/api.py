# -*- coding: utf-8 -*-
"""

    Supported external web service hooks

"""

import json
import logging

from hashlib import md5

from flask.views import View, request

logger = logging.getLogger(__name__)


class SendMessage(View):
    """ A webhook endpoint which sends a message to a Skype chat.

    A generic base class for other webhooks.

    Use HTTP POST parameters

    * msg

    * chat

    Other parameters are for compatibility reasons only and will be removed in the future.

    We validate only shared secret, not message signing.
    """

    methods = ['POST']

    def __init__(self, sevabot, shared_secret):
        self.sevabot = sevabot
        self.shared_secret = shared_secret

    #noinspection PyMethodOverriding
    def dispatch_request(self, *args, **kwargs):

        self.args = args
        self.kwargs = kwargs

        try:
            # BBB: Use only "chat" in the future
            chat_id = self.get_parameter('chat_id') or self.get_parameter('chat')

            if chat_id:
                if not self.validate(kwargs):
                    logger.error("Validation failed")
                    return "Validation failed!", 403, {"Content-type": "text/plain"}
                else:
                    msg = self.compose()

                    if not msg:
                        return "Message payload missing", 500, {"Content-type": "text/plain"}

                    self.sevabot.sendMessage(chat_id, msg)
                    logger.info("Successfully sent message %s" % msg)
                    return "OK"
            else:
                logger.error("Not enough parameters to send message (chat id missing)")
                return "Not enough parameters to send message!", 500, {"Content-type": "text/plain"}
        except Exception as e:
            logger.error(e)
            logger.exception(e)
            return (u"%s" % e).encode("utf-8"), 500, {"Content-type": "text/plain"}

    def get_parameter(self, key):
        """ Return parameter either from request or from url parameters """
        return request.form.get(key) or self.kwargs.get(key)

    def validate(self, kwargs):
        shared_secret = self.get_parameter('shared_secret')
        return shared_secret == self.shared_secret

    def compose(self):
        """
        Parse Skype chat message from the payload.

        .. note ::

            Use msg parameter. Others are provided for backward compatibility.

        """
        return request.form.get('message', '') or request.form.get('msg', '') or request.form.get('data', '')


class SendMessageMD5(SendMessage):
    """
    Send a MD5 signed chat message.

    HTTP POST parameters

    :param chat: Chat id

    :param msg: Message payload

    :param md5: MD5 checksum

    Make sure your client encodes message in UTF-8.
    """
    def validate(self, kwargs):

        # BBB: Use only "chat" in the future
        chat_id = self.get_parameter('chat_id') or self.get_parameter('chat')
        message = self.get_parameter('message') or self.get_parameter('msg')
        md5_value = self.get_parameter('md5')

        chat_encoded = chat_id.encode("utf-8")
        msg_encoded = message.encode("utf-8")

        md5_check = md5(chat_encoded + msg_encoded + self.shared_secret).hexdigest()

        return md5_check == md5_value


class SendMessageUnsigned(SendMessage):
    """
    HTTP endpoint to  send non-verified message to a chat.

    Takes both *chat_id* and *message* parameters as HTTP POST payload.

    .. warn::

        Allows third party to flood the chat if he/she gets hold of a chat id.

    HTTP POST parameters

    :param chat: Chat id

    :param msg: Message payload

    All other HTTP POST parameters are ignored.

    Make sure your client encodes message in UTF-8.
    """
    def validate(self, kwargs):
        return True


class GitHubPostCommit(SendMessage):
    """
    Handle post-commit hook from Github.

    https://help.github.com/articles/post-receive-hooks/
    """

    def compose(self):

        payload = json.loads(request.form["payload"])

        msg = u"(*) %s fresh commits - %s\n" % (payload["repository"]["name"], payload["repository"]["url"])
        for c in payload["commits"]:
            msg += u"(*) %s: %s\n%s\n" % (c["author"]["name"], c["message"], c["url"])

        return msg


class GitHubPullRequest(SendMessage):
    """
    Handle post-commit hook from Github.

    https://help.github.com/articles/post-receive-hooks/
    """

    def compose(self):

        payload = json.loads(request.form["payload"])

        if payload["action"] == "opened":
            msg = u"(*) %s new pull request %s from %s - %s\n" % (payload["repository"]["name"], payload["number"], payload["pull_request"]["user"]["login"], payload["pull_request"]["html_url"])
        elif payload["action"] == "closed":
            msg = u"(y) %s pull request %s merged by %s - %s\n" % (payload["repository"]["name"], payload["number"], payload["pull_request"]["merged_by"]["login"], payload["pull_request"]["html_url"])
        else:
            msg = u""
        return msg


def clean_git_ref(ref):
    return ref.replace("refs/heads/", "")


def github_user(obj, default=u"?"):
    if "name" in obj and obj["name"]:
        return obj["name"]
    elif "login" in obj and obj["login"]:
        return obj["login"]
    elif obj is basestring and obj:
        return obj
    else:
        return default


class GitHubAnyEvent(SendMessage):
    """
    Handle all event types hook from Github.

    https://developer.github.com/v3/activity/events/types/
    """

    def compose(self):
        payload = json.loads(request.form["payload"])
        event = request.headers["X-Github-Event"]

        url = None

        no_user = u"?"
        user = no_user
        if "sender" in payload:
            user = github_user(payload["sender"])

        no_repo = u"?"
        repo = no_repo
        if "repository" in payload:
            repo = payload["repository"]["name"]

        logger.info("GitHub {0} request on {1} (sender: {2}): {3}".format(event, repo, user, payload))

        no_message = u""
        msg = no_message
        icon = "default"

        # Represents a created branch, or tag.
        if event == "create":
            icon = "create"
            msg = u"%s created %s [%s]" % (user, payload["ref_type"], clean_git_ref(payload["ref"]))

        # Represents a deleted branch, or tag.
        elif event == "delete":
            icon = "delete"
            msg = u"%s deleted %s [%s]" % (user, payload["ref_type"], clean_git_ref(payload["ref"]))

        # Triggered when a Wiki page is created or updated.
        elif event == "gollum":
            icon = "update"
            msg = u"%s created/updated %s page(s) on the wiki:\n"\
                  % (user, len(payload["pages"]))
            for page in payload["pages"]:
                msg += u"   - %s: %s (%s)\n" % (page["action"], page["title"], page["html_url"])

        # Triggered when an issue comment is created.
        elif event == "issue_comment":
            msg = no_message

        # Triggered when a commit comment is created.
        elif event == "commit_comment":
            msg = no_message

        # Triggered when an issue is created, closed or reopened.
        elif event == "issues":
            action = payload["action"]
            if action == "closed":
                icon = "success"
            else:
                icon = "create"
            issue = payload["issue"]
            url = issue["html_url"]
            if user == no_user:
                user = github_user(issue["user"])
            msg = u"%s %s issue #%s: %s" % (user, action, issue["number"], issue["title"])

        # Triggered when a user is added as a collaborator to a repository.
        elif event == "member":
            msg = no_message

        # Triggered when a pull request is created, closed, reopened or synchronized.
        elif event == "pull_request":
            pr = payload["pull_request"]
            action = payload["action"]
            if action == "closed":
                if "merged_by" in pr and pr["merged_by"]:
                    icon = "success"
                    action = "accepted"
                    if user == no_user:
                        user = github_user(pr["merged_by"])
                else:
                    icon = "delete"
            elif action == "opened":
                icon = "create"
                if user == no_user:
                    user = github_user(pr["user"])
            elif action == "synchronize":
                icon = "updated"
                action = "updated"
            else:
                if not user:
                    user = github_user(pr["user"])
            if "changed_files" in pr:
                changed_files =  pr["changed_files"]
            else:
                changed_files = 0
            ref = clean_git_ref(pr["head"]["ref"])
            url = pr["html_url"]
            msg = u"%s %s PR #%s: {%s}, %s changed file(s) on branch [%s]"\
                  % (user, action, pr["number"], pr["title"], changed_files, ref)

        # Triggered when a comment is created on a portion of the unified diff of a pull request.
        elif event == "pull_request_review_comment":
            msg = no_message

        # Triggered when a repository branch is pushed to.
        elif event == "push":
            icon = "create"
            if user == no_user:
                user = u"%s (last commit author)" % github_user(payload["commits"][-1]["author"])
            if "size" in payload:
                size = payload["size"]
            else:
                size = len(payload["commits"])
            url = payload["compare"]
            msg = u"%s pushed %s commit(s) to [%s]"\
                  % (user, size, clean_git_ref(payload["ref"]))

        # Triggered when the status of a Git commit changes.
        elif event == "status":
            state = payload["state"]
            handle = True
            if state == "success":
                icon = "success"
            elif state == "failure" or state == "error":
                icon = "error"
            else:
                handle = False
            if handle:
                branches = []
                for branch in payload["branches"]:
                    branches.append(clean_git_ref(branch["ref"]))
                branches = u", ".join(branches)
                sha = payload["sha"][:5]
                if "target_url" in payload and payload["target_url"]:
                    url = payload["target_url"]
                msg = u"commit [%s] status switched to %s on branch(es) [%s]"\
                      % (sha, state.upper(), branches)

        # Triggered when a user is added to a team or when a repository is added to a team.
        elif event == "team_add":
            msg = no_message

        else:
            msg = no_message

        if msg != no_message:
            if icon == "create":
                icon = u"✸"
            elif icon == "delete":
                icon = u"✖"
            elif icon == "update":
                icon = u"✚"
            elif icon == "success":
                icon = u"✔"
            elif icon == "error":
                icon = u"☠"
            else:
                icon = u"❖"
            msg = u"%s %s ⥤ %s" % (icon, repo, msg)
            if url:
                msg += u" ☛ %s" % url
            if msg[-1] != u"\n":
                msg += u"\n"

        return msg


class JenkinsNotifier(SendMessage):

    """
    Handle requests from Jenkins notifier plugin

    https://wiki.jenkins-ci.org/display/JENKINS/Notification+Plugin
    """

    def compose(self):
        msg = None
        payload = request.json

        if payload is None:
            logger.error("Jenkins did not post a valid HTTP POST payload. Check the logs for further info.")
            return "Jenkins bad notification: Could not read HTTP POST data"
        # Filter out completed status, lots of unneeded noise
        if payload['build']['phase'] != 'COMPLETED':
            if payload['build']['status'] == 'SUCCESS':
                msg = u'Project: %s build #%d %s Status: %s - (sun) - %s\n' % (payload['name'], payload['build']['number'], payload['build']['phase'], payload['build']['status'], payload['build']['full_url'])
            elif payload['build']['status'] == 'FAILURE':
                msg = u'Project: %s build #%d %s Status: %s - (rain) - %s\n' % (payload['name'], payload['build']['number'], payload['build']['phase'], payload['build']['status'], payload['build']['full_url'])
            else:
                msg = u'Project: %s build #%d %s Status: %s - - %s\n' % (payload['name'], payload['build']['number'], payload['build']['phase'], payload['build']['status'], payload['build']['full_url'])

        return msg


class TeamcityWebHook(SendMessage):

    def compose(self):
        payload = json.loads(request.data)
        build = payload.get('build')

        message = '%s\n%s' % (build.get('message'), build.get('buildStatusUrl'))

        return message


def configure(sevabot, settings, server):
    """
    Install Flask webhook routing
    """

       # this url rules for sending message. Parameters can be in url or in request
    server.add_url_rule('/message/', view_func=SendMessage.as_view(str('send_message'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    server.add_url_rule('/message_unsigned/', view_func=SendMessageUnsigned.as_view(str('send_message_unsigned'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    server.add_url_rule('/message/<string:chat_id>/', view_func=SendMessage.as_view(str('send_message_1'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    server.add_url_rule('/message/<string:chat_id>/<string:shared_secret>/', view_func=SendMessage.as_view(str('send_message_2'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    # XXX: Remove
    server.add_url_rule('/zapier/<string:chat_id>/<string:shared_secret>/', view_func=SendMessage.as_view(str('send_message_3'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    # rule for sending md5 signed message
    server.add_url_rule('/msg/', view_func=SendMessageMD5.as_view(str('send_message_md5'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    # rule for notifying on github commits
    server.add_url_rule('/github-post-commit/<string:chat_id>/<string:shared_secret>/', view_func=GitHubPostCommit.as_view(str('send_message_github_1'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    # rule for notifying on github pull requests
    server.add_url_rule('/github-pull-request/<string:chat_id>/<string:shared_secret>/', view_func=GitHubPullRequest.as_view(str('send_message_github_2'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    # rule for notifying on github any event
    server.add_url_rule('/github-any-event/<string:chat_id>/<string:shared_secret>/', view_func=GitHubAnyEvent.as_view(str('send_message_github_3'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    server.add_url_rule('/jenkins-notifier/<string:chat_id>/<string:shared_secret>/', view_func=JenkinsNotifier.as_view(str('send_message_jenkins'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))

    server.add_url_rule('/teamcity/<string:chat_id>/<string:shared_secret>/', view_func=TeamcityWebHook.as_view(str('send_message_teamcity'), sevabot=sevabot, shared_secret=settings.SHARED_SECRET))
